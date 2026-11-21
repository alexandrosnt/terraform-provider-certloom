package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type teamResource struct{ base }

type teamModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Contact types.String `tfsdk:"contact"`
}

func newTeamResource() resource.Resource { return &teamResource{} }

func (r *teamResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_team"
}

func (r *teamResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A team that owns certificate lineages and endpoints. Findings and alerts are routed by owner.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Unique team name.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"contact": schema.StringAttribute{
				MarkdownDescription: "How to reach the team, for example an email address or chat channel.",
				Optional:            true,
			},
		},
	}
}

func idAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: "Identifier assigned by certloom.",
		Computed:            true,
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func (m *teamModel) set(t *client.Team) {
	m.ID, m.Name, m.Contact = types.StringValue(t.ID), types.StringValue(t.Name), optString(t.Contact)
}

func (r *teamResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m teamModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.CreateTeam(ctx, m.Name.ValueString(), m.Contact.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "create team", err)
		return
	}
	m.set(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *teamResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m teamModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.GetTeam(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read team", err)
		return
	}
	m.set(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *teamResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m teamModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.UpdateTeam(ctx, m.ID.ValueString(), client.TeamPatch{Name: ptr(m.Name.ValueString()), Contact: ptr(m.Contact.ValueString())})
	if err != nil {
		apiError(&resp.Diagnostics, "update team", err)
		return
	}
	m.set(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *teamResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m teamModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteTeam(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete team", err)
	}
}

func (r *teamResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}
