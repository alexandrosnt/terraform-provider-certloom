package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

// Certificate templates and the monitoring policy are YAML documents the
// server validates, plans and stores as versions. The provider sends the
// document text as is and reads back the stored source, so any change made
// outside Terraform shows as a diff.

// ---------- certloom_template ----------

type templateResource struct{ base }

type templateModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	Document types.String `tfsdk:"document"`
	Version  types.Int64  `tfsdk:"version"`
}

func newTemplateResource() resource.Resource { return &templateResource{} }

func (r *templateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_template"
}

func (r *templateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A certificate template: the issuer, key type, SAN rules and renewal settings that " +
			"deployments inherit. The server rejects a template that existing deployments would violate.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Template name. Must match `metadata.name` in the document.", Required: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"document": schema.StringAttribute{
				MarkdownDescription: "Template document in YAML (`kind: CertificateTemplate`), for example from `file()`.",
				Required:            true,
			},
			"version": schema.Int64Attribute{MarkdownDescription: "Current template version.", Computed: true},
		},
	}
}

func (r *templateResource) apply(ctx context.Context, m *templateModel) error {
	p, err := r.client.ApplyTemplate(ctx, []byte(m.Document.ValueString()), false)
	if err != nil {
		return err
	}
	if p.Name != m.Name.ValueString() {
		return fmt.Errorf("the document names template %q but name is %q", p.Name, m.Name.ValueString())
	}
	if !p.Applied {
		return fmt.Errorf("template not applied; violations: %s", p.Violations)
	}
	t, err := r.client.GetTemplate(ctx, p.Name)
	if err != nil {
		return err
	}
	m.ID, m.Version = types.StringValue(t.ID), types.Int64Value(int64(t.Version))
	return nil
}

func (r *templateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		apiError(&resp.Diagnostics, "apply template", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *templateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.GetTemplate(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read template", err)
		return
	}
	m.ID, m.Name, m.Version = types.StringValue(t.ID), types.StringValue(t.Name), types.Int64Value(int64(t.Version))
	m.Document = types.StringValue(t.Source)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *templateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		apiError(&resp.Diagnostics, "apply template", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *templateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteTemplate(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete template", err)
	}
}

func (r *templateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

// ---------- certloom_policy ----------

// defaultPolicy is what deleting the resource applies: the built-in defaults.
const defaultPolicy = "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {}\n"

const policyID = "policy"

type policyResource struct{ base }

type policyModel struct {
	ID       types.String `tfsdk:"id"`
	Document types.String `tfsdk:"document"`
	Version  types.Int64  `tfsdk:"version"`
}

func newPolicyResource() resource.Resource { return &policyResource{} }

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The organization's monitoring policy (one per organization): expiry thresholds, key and " +
			"chain rules, escalation, approvals and retention. Each apply stores a new policy version. Destroying " +
			"the resource restores the built-in defaults. Declare it only once.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{MarkdownDescription: "Always `policy`.", Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"document": schema.StringAttribute{
				MarkdownDescription: "Policy document in YAML (`kind: MonitoringPolicy`), for example from `file()`.",
				Required:            true,
			},
			"version": schema.Int64Attribute{MarkdownDescription: "Policy version created by the last apply.", Computed: true},
		},
	}
}

func (r *policyResource) apply(ctx context.Context, m *policyModel) error {
	p, err := r.client.ApplyPolicy(ctx, []byte(m.Document.ValueString()), false)
	if err != nil {
		return err
	}
	m.ID = types.StringValue(policyID)
	m.Version = types.Int64Value(int64(max(p.Version, p.CurrentVersion)))
	return nil
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		apiError(&resp.Diagnostics, "apply policy", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.GetPolicy(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "read policy", err)
		return
	}
	if p.Version == 0 { // defaults in effect: nothing to manage
		resp.State.RemoveResource(ctx)
		return
	}
	m.ID, m.Version = types.StringValue(policyID), types.Int64Value(int64(p.Version))
	// The server keeps the source as sent; a document applied by Terraform
	// therefore reads back unchanged.
	if strings.TrimSpace(p.Source) != strings.TrimSpace(m.Document.ValueString()) {
		m.Document = types.StringValue(p.Source)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		apiError(&resp.Diagnostics, "apply policy", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if _, err := r.client.ApplyPolicy(ctx, []byte(defaultPolicy), false); err != nil {
		apiError(&resp.Diagnostics, "restore default policy", err)
	}
}

func (r *policyResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathID, policyID)...)
}
