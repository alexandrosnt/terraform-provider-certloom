package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type scopeResource struct{ base }

type scopeModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	AllowCIDRs     types.List   `tfsdk:"allow_cidrs"`
	AllowHosts     types.List   `tfsdk:"allow_hosts"`
	AllowLoopback  types.Bool   `tfsdk:"allow_loopback"`
	AllowPrivate   types.Bool   `tfsdk:"allow_private"`
	AllowLinkLocal types.Bool   `tfsdk:"allow_link_local"`
	Ports          types.List   `tfsdk:"ports"`
}

func newScopeResource() resource.Resource { return &scopeResource{} }

func (r *scopeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope"
}

func (r *scopeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	flag := func(desc string) schema.BoolAttribute {
		return schema.BoolAttribute{MarkdownDescription: desc, Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A probe scope: which hosts, networks and ports certloom may connect to when it checks " +
			"endpoints. Every endpoint belongs to one scope. Loopback, private and link-local addresses are refused " +
			"unless the scope allows them, so a scope cannot be used to reach internal services by accident.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttribute(),
			"name": schema.StringAttribute{MarkdownDescription: "Unique scope name.", Required: true},
			"allow_cidrs": schema.ListAttribute{
				MarkdownDescription: "Networks endpoints may resolve to, in CIDR notation.",
				ElementType:         types.StringType, Optional: true,
				Validators: []validator.List{listvalidator.SizeAtLeast(1)},
			},
			"allow_hosts": schema.ListAttribute{
				MarkdownDescription: "Host names endpoints may use; `*.example.com` matches one label.",
				ElementType:         types.StringType, Optional: true,
				Validators: []validator.List{listvalidator.SizeAtLeast(1)},
			},
			"allow_loopback":   flag("Allow loopback addresses."),
			"allow_private":    flag("Allow private (RFC 1918, ULA) addresses."),
			"allow_link_local": flag("Allow link-local addresses, including cloud metadata services. Rarely what you want."),
			"ports": schema.ListAttribute{
				MarkdownDescription: "Allowed ports. When unset, only 443 is allowed.",
				ElementType:         types.Int64Type, Optional: true,
				Validators: []validator.List{listvalidator.SizeAtLeast(1),
					listvalidator.ValueInt64sAre(int64validator.Between(1, 65535))},
			},
		},
	}
}

func (m *scopeModel) config(ctx context.Context, diags *diag.Diagnostics) client.ScopeConfig {
	cfg := client.ScopeConfig{
		AllowCIDRs:     listStrings(ctx, m.AllowCIDRs, diags),
		AllowHosts:     listStrings(ctx, m.AllowHosts, diags),
		AllowLoopback:  m.AllowLoopback.ValueBool(),
		AllowPrivate:   m.AllowPrivate.ValueBool(),
		AllowLinkLocal: m.AllowLinkLocal.ValueBool(),
	}
	if !m.Ports.IsNull() && !m.Ports.IsUnknown() {
		var ports []int64
		diags.Append(m.Ports.ElementsAs(ctx, &ports, false)...)
		for _, p := range ports {
			cfg.Ports = append(cfg.Ports, int(p))
		}
	}
	return cfg
}

func (m *scopeModel) set(ctx context.Context, s *client.Scope, diags *diag.Diagnostics) {
	m.ID, m.Name = types.StringValue(s.ID), types.StringValue(s.Name)
	m.AllowCIDRs = stringList(ctx, s.Config.AllowCIDRs, diags)
	m.AllowHosts = stringList(ctx, s.Config.AllowHosts, diags)
	m.AllowLoopback = types.BoolValue(s.Config.AllowLoopback)
	m.AllowPrivate = types.BoolValue(s.Config.AllowPrivate)
	m.AllowLinkLocal = types.BoolValue(s.Config.AllowLinkLocal)
	m.Ports = types.ListNull(types.Int64Type)
	if len(s.Config.Ports) > 0 {
		ports := make([]int64, len(s.Config.Ports))
		for i, p := range s.Config.Ports {
			ports[i] = int64(p)
		}
		l, d := types.ListValueFrom(ctx, types.Int64Type, ports)
		diags.Append(d...)
		m.Ports = l
	}
}

func (r *scopeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m scopeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	cfg := m.config(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.CreateScope(ctx, m.Name.ValueString(), cfg)
	if err != nil {
		apiError(&resp.Diagnostics, "create scope", err)
		return
	}
	m.set(ctx, s, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *scopeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m scopeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.GetScope(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read scope", err)
		return
	}
	m.set(ctx, s, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *scopeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m scopeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	cfg := m.config(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.UpdateScope(ctx, m.ID.ValueString(), client.ScopePatch{Name: ptr(m.Name.ValueString()), Config: &cfg})
	if err != nil {
		apiError(&resp.Diagnostics, "update scope", err)
		return
	}
	m.set(ctx, s, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *scopeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m scopeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteScope(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete scope", err)
	}
}

func (r *scopeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}
