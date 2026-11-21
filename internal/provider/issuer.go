package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type issuerResource struct{ base }

type issuerModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	DirectoryURL     types.String `tfsdk:"directory_url"`
	Email            types.String `tfsdk:"email"`
	AgreeTOS         types.Bool   `tfsdk:"agree_tos"`
	Profile          types.String `tfsdk:"profile"`
	EABMode          types.String `tfsdk:"eab_mode"`
	EABKID           types.String `tfsdk:"eab_kid"`
	EABHMACWO        types.String `tfsdk:"eab_hmac_wo"`
	EABHMACWOVersion types.Int64  `tfsdk:"eab_hmac_wo_version"`
}

func newIssuerResource() resource.Resource { return &issuerResource{} }

func (r *issuerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_issuer"
}

func (r *issuerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An ACME certificate authority that deployments renew from. The directory URL and the " +
			"terms-of-service decision are fixed; a different CA is a new issuer.\n\n" +
			"For CAs that require External Account Binding, set `eab_mode = \"reusable\"` with `eab_kid` and the " +
			"write-only `eab_hmac_wo`. The HMAC is sealed on the server and never stored in plan or state; bump " +
			"`eab_hmac_wo_version` to send a new one. `single_use` keys are managed with the certloom CLI.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttribute(),
			"name": schema.StringAttribute{MarkdownDescription: "Unique issuer name.", Required: true},
			"directory_url": schema.StringAttribute{
				MarkdownDescription: "ACME directory URL (https).", Required: true,
				Validators:    []validator.String{stringvalidator.RegexMatches(httpsURL, "must be an https URL")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"email": schema.StringAttribute{MarkdownDescription: "Contact address for new ACME accounts.", Optional: true},
			"agree_tos": schema.BoolAttribute{
				MarkdownDescription: "Must be `true`: records that you accept the CA's terms of service.", Required: true,
				Validators:    []validator.Bool{mustBeTrue{}},
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"profile": schema.StringAttribute{MarkdownDescription: "ACME certificate profile to request, if the CA offers profiles.", Optional: true},
			"eab_mode": schema.StringAttribute{
				MarkdownDescription: "External Account Binding: `none`, `reusable` or `single_use`.", Optional: true, Computed: true,
				Default:    stringdefault.StaticString(client.EABNone),
				Validators: []validator.String{stringvalidator.OneOf(client.EABNone, client.EABReusable, client.EABSingleUse)},
			},
			"eab_kid": schema.StringAttribute{
				MarkdownDescription: "EAB key identifier from the CA. Required for `reusable`.", Optional: true,
				Validators: []validator.String{stringvalidator.AlsoRequires(path.MatchRoot("eab_hmac_wo_version"))},
			},
			"eab_hmac_wo": schema.StringAttribute{
				MarkdownDescription: "EAB HMAC key from the CA (base64url). Write-only: never stored in plan or state.",
				Optional:            true, Sensitive: true, WriteOnly: true,
				Validators: []validator.String{stringvalidator.AlsoRequires(path.MatchRoot("eab_hmac_wo_version"), path.MatchRoot("eab_kid"))},
			},
			"eab_hmac_wo_version": schema.Int64Attribute{
				MarkdownDescription: "Change this number to send `eab_kid` and `eab_hmac_wo` again, for example after the CA rotates the key.",
				Optional:            true,
				Validators:          []validator.Int64{int64validator.AtLeast(1)},
			},
		},
	}
}

func (m *issuerModel) set(i *client.Issuer) {
	m.ID, m.Name, m.DirectoryURL = types.StringValue(i.ID), types.StringValue(i.Name), types.StringValue(i.DirectoryURL)
	m.Email, m.AgreeTOS, m.Profile = optString(i.Email), types.BoolValue(i.AgreeTOS), optString(i.Profile)
	m.EABMode, m.EABKID = types.StringValue(i.EABMode), optString(i.EABKID)
	m.EABHMACWO = types.StringNull()
}

// setEAB sends the EAB settings. The HMAC comes from the configuration,
// the only place a write-only value is available.
func (r *issuerResource) setEAB(ctx context.Context, cfg issuerModel, id string) (*client.Issuer, error) {
	return r.client.SetIssuerEAB(ctx, id, cfg.EABMode.ValueString(), cfg.EABKID.ValueString(), cfg.EABHMACWO.ValueString())
}

func (r *issuerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m, cfg issuerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	i, err := r.client.CreateIssuer(ctx, client.IssuerInput{Name: m.Name.ValueString(), DirectoryURL: m.DirectoryURL.ValueString(),
		Email: m.Email.ValueString(), AgreeTOS: m.AgreeTOS.ValueBool(), Profile: m.Profile.ValueString()})
	if err != nil {
		apiError(&resp.Diagnostics, "create issuer", err)
		return
	}
	if m.EABMode.ValueString() != client.EABNone {
		cfg.EABMode = m.EABMode
		withEAB, err := r.setEAB(ctx, cfg, i.ID)
		if err != nil {
			// Keep the issuer in state; Terraform taints it and replaces it
			// on the next apply instead of leaving an orphan behind.
			m.set(i)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			apiError(&resp.Diagnostics, "set issuer EAB", err)
			return
		}
		i = withEAB
	}
	version := m.EABHMACWOVersion
	m.set(i)
	m.EABHMACWOVersion = version
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *issuerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m issuerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	i, err := r.client.GetIssuer(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read issuer", err)
		return
	}
	m.set(i)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *issuerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, cfg issuerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	i, err := r.client.UpdateIssuer(ctx, id, client.IssuerPatch{Name: ptr(plan.Name.ValueString()),
		Email: ptr(plan.Email.ValueString()), Profile: ptr(plan.Profile.ValueString())})
	if err != nil {
		apiError(&resp.Diagnostics, "update issuer", err)
		return
	}
	if !plan.EABMode.Equal(state.EABMode) || !plan.EABKID.Equal(state.EABKID) || !plan.EABHMACWOVersion.Equal(state.EABHMACWOVersion) {
		cfg.EABMode = plan.EABMode
		if i, err = r.setEAB(ctx, cfg, id); err != nil {
			apiError(&resp.Diagnostics, "set issuer EAB", err)
			return
		}
	}
	plan.set(i)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *issuerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m issuerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteIssuer(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete issuer", err)
	}
}

func (r *issuerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}
