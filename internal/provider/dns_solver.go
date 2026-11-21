package provider

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type dnsSolverResource struct{ base }

type dnsSolverModel struct {
	ID              types.String         `tfsdk:"id"`
	Name            types.String         `tfsdk:"name"`
	Provider        types.String         `tfsdk:"provider_type"`
	Plugin          types.String         `tfsdk:"plugin"`
	PluginSHA256    types.String         `tfsdk:"plugin_sha256"`
	Zones           types.List           `tfsdk:"zones"`
	Config          jsontypes.Normalized `tfsdk:"config"`
	Credential      types.String         `tfsdk:"credential"`
	SecretWO        types.String         `tfsdk:"secret_wo"`
	SecretWOVersion types.Int64          `tfsdk:"secret_wo_version"`
	AgentIDs        types.Set            `tfsdk:"agent_ids"`
}

func newDNSSolverResource() resource.Resource { return &dnsSolverResource{} }

func (r *dnsSolverResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns_solver"
}

func (r *dnsSolverResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A DNS-01 solver that agents use to answer ACME challenges for the listed zones.\n\n" +
			"With `credential = \"stored\"` the DNS provider credential is passed in the write-only `secret_wo` " +
			"argument. certloom seals it to the assigned agents; it is never written to plan or state and never " +
			"returned by the API. Bump `secret_wo_version` to rotate it. With `credential = \"ambient\"` (plugins " +
			"only) the agent uses its host's own cloud identity and no secret is sent.\n\n" +
			"Only the secret and the agent assignments can change in place; any other change replaces the solver.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttribute(),
			"name": schema.StringAttribute{MarkdownDescription: "Unique solver name.", Required: true, PlanModifiers: replace},
			"provider_type": schema.StringAttribute{
				MarkdownDescription: "`rfc2136`, `cloudflare` or `plugin`.", Required: true, PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.OneOf("rfc2136", "cloudflare", "plugin")},
			},
			"plugin": schema.StringAttribute{
				MarkdownDescription: "Absolute path of the solver plugin on the agent hosts (`plugin` only).",
				Optional:            true, PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.AlsoRequires(path.MatchRoot("plugin_sha256"))},
			},
			"plugin_sha256": schema.StringAttribute{
				MarkdownDescription: "Hex SHA-256 of the plugin binary; agents refuse a plugin that does not match.",
				Optional:            true, PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.RegexMatches(sha256Hex, "must be a lowercase hex SHA-256 digest")},
			},
			"zones": schema.ListAttribute{
				MarkdownDescription: "DNS zones the solver may write, lowercase without a trailing dot.",
				ElementType:         types.StringType, Required: true,
				Validators:    []validator.List{listvalidator.SizeAtLeast(1)},
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"config": schema.StringAttribute{
				MarkdownDescription: "Non-secret provider settings as JSON (`jsonencode`), for example the RFC 2136 server and TSIG key name.",
				CustomType:          jsontypes.NormalizedType{}, Optional: true, PlanModifiers: replace,
			},
			"credential": schema.StringAttribute{
				MarkdownDescription: "`stored` (secret in `secret_wo`) or `ambient` (the agent host's identity; plugins only).",
				Required:            true, PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.OneOf("stored", "ambient")},
			},
			"secret_wo": schema.StringAttribute{
				MarkdownDescription: "Provider credential as a JSON object of strings, for example " +
					"`jsonencode({api_token = var.cloudflare_token})`. Write-only: never stored in plan or state. " +
					"Required on create when `credential` is `stored`.",
				Optional: true, Sensitive: true, WriteOnly: true,
				Validators: []validator.String{stringvalidator.AlsoRequires(path.MatchRoot("secret_wo_version"))},
			},
			"secret_wo_version": schema.Int64Attribute{
				MarkdownDescription: "Change this number to send a new `secret_wo`.",
				Optional:            true, Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"agent_ids": schema.SetAttribute{
				MarkdownDescription: "Agents allowed to use this solver (`data.certloom_agent.<name>.id`).",
				ElementType:         types.StringType, Optional: true,
			},
		},
	}
}

func (m *dnsSolverModel) set(ctx context.Context, s *client.DNSSolver, diags *diag.Diagnostics) {
	m.ID, m.Name, m.Provider = types.StringValue(s.ID), types.StringValue(s.Name), types.StringValue(s.Provider)
	m.Plugin, m.PluginSHA256, m.Credential = optString(s.Plugin), optString(s.PluginSHA256), types.StringValue(s.Credential)
	m.Zones = stringList(ctx, s.Zones, diags)
	m.Config = jsontypes.NewNormalizedNull()
	if len(s.Config) > 0 {
		b, err := json.Marshal(s.Config)
		if err != nil {
			diags.AddError("Cannot encode solver config", err.Error())
		}
		m.Config = jsontypes.NewNormalizedValue(string(b))
	}
	m.SecretWO = types.StringNull()
	m.AgentIDs = stringSet(ctx, s.Agents, diags)
}

func (r *dnsSolverResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m, cfg dnsSolverModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	in := client.DNSSolverInput{Name: m.Name.ValueString(), Provider: m.Provider.ValueString(), Plugin: m.Plugin.ValueString(),
		PluginSHA256: m.PluginSHA256.ValueString(), Zones: listStrings(ctx, m.Zones, &resp.Diagnostics),
		Credential: m.Credential.ValueString()}
	if !m.Config.IsNull() {
		resp.Diagnostics.Append(m.Config.Unmarshal(&in.Config)...)
	}
	if !cfg.SecretWO.IsNull() {
		in.Secret = json.RawMessage(cfg.SecretWO.ValueString())
	}
	agents := setStrings(ctx, m.AgentIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.CreateDNSSolver(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "create DNS solver", err)
		return
	}
	version := m.SecretWOVersion
	for _, a := range agents {
		if err := r.client.AssignDNSSolver(ctx, s.ID, a); err != nil {
			apiError(&resp.Diagnostics, "assign DNS solver to agent "+a, err)
			break
		}
	}
	if fresh, err := r.client.GetDNSSolver(ctx, s.ID); err == nil {
		s = fresh
	}
	m.set(ctx, s, &resp.Diagnostics)
	m.SecretWOVersion = version
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *dnsSolverResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m dnsSolverModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.GetDNSSolver(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read DNS solver", err)
		return
	}
	m.set(ctx, s, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *dnsSolverResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, cfg dnsSolverModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	if !plan.SecretWOVersion.Equal(state.SecretWOVersion) && !cfg.SecretWO.IsNull() {
		if err := r.client.SetDNSSolverSecret(ctx, id, json.RawMessage(cfg.SecretWO.ValueString())); err != nil {
			apiError(&resp.Diagnostics, "set DNS solver secret", err)
			return
		}
	}
	want := setStrings(ctx, plan.AgentIDs, &resp.Diagnostics)
	have := setStrings(ctx, state.AgentIDs, &resp.Diagnostics)
	for _, a := range want {
		if !slices.Contains(have, a) {
			if err := r.client.AssignDNSSolver(ctx, id, a); err != nil {
				apiError(&resp.Diagnostics, "assign DNS solver to agent "+a, err)
				return
			}
		}
	}
	for _, a := range have {
		if !slices.Contains(want, a) {
			if err := r.client.UnassignDNSSolver(ctx, id, a); err != nil && !client.IsNotFound(err) {
				apiError(&resp.Diagnostics, "unassign DNS solver from agent "+a, err)
				return
			}
		}
	}
	s, err := r.client.GetDNSSolver(ctx, id)
	if err != nil {
		apiError(&resp.Diagnostics, "read DNS solver", err)
		return
	}
	version := plan.SecretWOVersion
	plan.set(ctx, s, &resp.Diagnostics)
	plan.SecretWOVersion = version
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dnsSolverResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m dnsSolverModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteDNSSolver(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete DNS solver", err)
	}
}

func (r *dnsSolverResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}
