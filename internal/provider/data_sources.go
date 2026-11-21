package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var pathID = path.Root("id")

// Lookups by name, for objects created outside this configuration.

func lookupSchema(desc string, extra map[string]schema.Attribute) schema.Schema {
	attrs := map[string]schema.Attribute{
		"id":   schema.StringAttribute{MarkdownDescription: "Identifier.", Computed: true},
		"name": schema.StringAttribute{MarkdownDescription: "Name to look up.", Required: true},
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return schema.Schema{MarkdownDescription: desc, Attributes: attrs}
}

func computedString(desc string) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: desc, Computed: true}
}

// ---------- certloom_team ----------

type teamDataSource struct{ dsBase }

func newTeamDataSource() datasource.DataSource { return &teamDataSource{} }

func (d *teamDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_team"
}

func (d *teamDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = lookupSchema("Looks up a team by name.", map[string]schema.Attribute{"contact": computedString("Team contact.")})
}

func (d *teamDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m teamModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := d.client.GetTeam(ctx, m.Name.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "look up team", err)
		return
	}
	m.set(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------- certloom_scope ----------

type scopeDataSource struct{ dsBase }

type scopeLookup struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
}

func newScopeDataSource() datasource.DataSource { return &scopeDataSource{} }

func (d *scopeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope"
}

func (d *scopeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = lookupSchema("Looks up a probe scope by name.", nil)
}

func (d *scopeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m scopeLookup
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := d.client.GetScope(ctx, m.Name.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "look up scope", err)
		return
	}
	m.ID = types.StringValue(s.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------- certloom_issuer ----------

type issuerDataSource struct{ dsBase }

type issuerLookup struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	DirectoryURL types.String `tfsdk:"directory_url"`
	EABMode      types.String `tfsdk:"eab_mode"`
}

func newIssuerDataSource() datasource.DataSource { return &issuerDataSource{} }

func (d *issuerDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_issuer"
}

func (d *issuerDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = lookupSchema("Looks up an ACME issuer by name.", map[string]schema.Attribute{
		"directory_url": computedString("ACME directory URL."),
		"eab_mode":      computedString("External Account Binding mode."),
	})
}

func (d *issuerDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m issuerLookup
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	i, err := d.client.GetIssuer(ctx, m.Name.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "look up issuer", err)
		return
	}
	m.ID, m.DirectoryURL, m.EABMode = types.StringValue(i.ID), types.StringValue(i.DirectoryURL), types.StringValue(i.EABMode)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------- certloom_agent ----------

type agentDataSource struct{ dsBase }

type agentLookup struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	State    types.String `tfsdk:"state"`
	Health   types.String `tfsdk:"health"`
	Hostname types.String `tfsdk:"hostname"`
}

func newAgentDataSource() datasource.DataSource { return &agentDataSource{} }

func (d *agentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent"
}

func (d *agentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = lookupSchema("Looks up an enrolled agent by name. Agents enroll themselves with a one-time token; "+
		"they are not created by Terraform.", map[string]schema.Attribute{
		"state":    computedString("`active` or `revoked`."),
		"health":   computedString("Liveness from the last heartbeat."),
		"hostname": computedString("Host name the agent reported."),
	})
}

func (d *agentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m agentLookup
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	agents, err := d.client.ListAgents(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "list agents", err)
		return
	}
	for _, a := range agents {
		if a.Name == m.Name.ValueString() && a.State == "active" {
			m.ID, m.State, m.Health, m.Hostname = types.StringValue(a.ID), types.StringValue(a.State), types.StringValue(a.Health), types.StringValue(a.Hostname)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.Diagnostics.AddAttributeError(path.Root("name"), "Agent not found", "No active agent is named "+m.Name.ValueString()+".")
}
