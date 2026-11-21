package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type endpointResource struct{ base }

type endpointModel struct {
	ID              types.String `tfsdk:"id"`
	Host            types.String `tfsdk:"host"`
	Port            types.Int64  `tfsdk:"port"`
	SNI             types.String `tfsdk:"sni"`
	ScopeID         types.String `tfsdk:"scope_id"`
	TeamID          types.String `tfsdk:"team_id"`
	LineageID       types.String `tfsdk:"lineage_id"`
	IntervalSeconds types.Int64  `tfsdk:"interval_seconds"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	Version         types.Int64  `tfsdk:"version"`
}

func newEndpointResource() resource.Resource { return &endpointResource{} }

func (r *endpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_endpoint"
}

func (r *endpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A TLS endpoint certloom probes on a schedule. Each probe records the served chain and " +
			"raises findings (expiry, hostname mismatch, weak keys, chain problems). Host, port and SNI identify the " +
			"endpoint; changing them replaces it. Deleting an endpoint resolves its open findings.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttribute(),
			"host": schema.StringAttribute{MarkdownDescription: "Host name or IP address to connect to.", Required: true, PlanModifiers: replace},
			"port": schema.Int64Attribute{
				MarkdownDescription: "TCP port.", Optional: true, Computed: true, Default: int64default.StaticInt64(443),
				Validators:    []validator.Int64{int64validator.Between(1, 65535)},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"sni": schema.StringAttribute{
				MarkdownDescription: "Server name to send in the TLS handshake when it differs from `host`.",
				Optional:            true, PlanModifiers: replace,
			},
			"scope_id": schema.StringAttribute{
				MarkdownDescription: "Probe scope (`certloom_scope.<name>.id`). The scope must allow the host and port.",
				Required:            true,
			},
			"team_id":    schema.StringAttribute{MarkdownDescription: "Owning team (`certloom_team.<name>.id`).", Optional: true},
			"lineage_id": schema.StringAttribute{MarkdownDescription: "Lineage the endpoint is expected to serve.", Optional: true},
			"interval_seconds": schema.Int64Attribute{
				MarkdownDescription: "Seconds between probes. Defaults to six hours.", Optional: true, Computed: true,
				Default: int64default.StaticInt64(21600), Validators: []validator.Int64{int64validator.AtLeast(60)},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the endpoint is probed.", Optional: true, Computed: true, Default: booldefault.StaticBool(true),
			},
			"version": schema.Int64Attribute{
				MarkdownDescription: "Configuration version. Updates are sent with `If-Match`, so a change made outside " +
					"Terraform since the last refresh fails the apply instead of being overwritten.",
				Computed: true,
			},
		},
	}
}

func (m *endpointModel) set(e *client.Endpoint) {
	m.ID, m.Host, m.Port = types.StringValue(e.ID), types.StringValue(e.Host), types.Int64Value(int64(e.Port))
	m.SNI, m.ScopeID = optString(e.SNI), types.StringValue(e.ScopeID)
	m.TeamID, m.LineageID = optStringPtr(e.TeamID), optStringPtr(e.LineageID)
	m.IntervalSeconds, m.Enabled = types.Int64Value(int64(e.IntervalSeconds)), types.BoolValue(e.Enabled)
	m.Version = types.Int64Value(e.Version)
}

func (r *endpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m endpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	e, err := r.client.CreateEndpoint(ctx, client.EndpointInput{Host: m.Host.ValueString(), Port: int(m.Port.ValueInt64()),
		SNI: m.SNI.ValueString(), Scope: m.ScopeID.ValueString(), Team: m.TeamID.ValueString(),
		Lineage: m.LineageID.ValueString(), IntervalSeconds: int(m.IntervalSeconds.ValueInt64())})
	if err != nil {
		apiError(&resp.Diagnostics, "create endpoint", err)
		return
	}
	// New endpoints start enabled; disabling is a separate update.
	if !m.Enabled.ValueBool() {
		if e, err = r.client.UpdateEndpoint(ctx, e.ID, client.EndpointPatch{Enabled: ptr(false)}, e.Version); err != nil {
			apiError(&resp.Diagnostics, "disable endpoint", err)
			return
		}
	}
	m.set(e)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *endpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m endpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	e, err := r.client.GetEndpoint(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read endpoint", err)
		return
	}
	m.set(e)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *endpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state endpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := client.EndpointPatch{
		Scope:           ptr(plan.ScopeID.ValueString()),
		Team:            ptr(plan.TeamID.ValueString()), // "" clears
		Lineage:         ptr(plan.LineageID.ValueString()),
		IntervalSeconds: ptr(int(plan.IntervalSeconds.ValueInt64())),
		Enabled:         ptr(plan.Enabled.ValueBool()),
	}
	e, err := r.client.UpdateEndpoint(ctx, state.ID.ValueString(), p, state.Version.ValueInt64())
	if client.IsPreconditionFailed(err) {
		resp.Diagnostics.AddError("Endpoint changed outside Terraform",
			"The endpoint was modified since the last refresh. Run terraform plan again to see the current settings.")
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "update endpoint", err)
		return
	}
	plan.set(e)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *endpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m endpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteEndpoint(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete endpoint", err)
	}
}

func (r *endpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}
