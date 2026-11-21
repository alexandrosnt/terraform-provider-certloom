package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type channelResource struct{ base }

type channelModel struct {
	ID            types.String         `tfsdk:"id"`
	Name          types.String         `tfsdk:"name"`
	Kind          types.String         `tfsdk:"kind"`
	Config        jsontypes.Normalized `tfsdk:"config"`
	CredentialRef types.String         `tfsdk:"credential_ref"`
	MinSeverity   types.String         `tfsdk:"min_severity"`
	Enabled       types.Bool           `tfsdk:"enabled"`
}

func newChannelResource() resource.Resource { return &channelResource{} }

func (r *channelResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_channel"
}

func (r *channelResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A notification channel for alerts. The channel never stores a secret: `credential_ref` " +
			"names where the certloom server reads one (for example `env:CERTLOOM_WEBHOOK_SECRET`), so nothing " +
			"secret reaches Terraform state. A channel named in the active policy cannot be renamed or deleted.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttribute(),
			"name": schema.StringAttribute{MarkdownDescription: "Unique channel name, as the policy refers to it.", Required: true},
			"kind": schema.StringAttribute{
				MarkdownDescription: "`webhook` or `email`. Changing it replaces the channel.", Required: true,
				Validators:    []validator.String{stringvalidator.OneOf("webhook", "email")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"config": schema.StringAttribute{
				MarkdownDescription: "Non-secret settings as JSON, usually written with `jsonencode`. Webhook: " +
					"`{url = \"https://...\"}`. Email: SMTP host, port, from and to addresses.",
				CustomType: jsontypes.NormalizedType{}, Required: true,
			},
			"credential_ref": schema.StringAttribute{
				MarkdownDescription: "Reference to the secret on the server, such as `env:NAME` or `file:/path`.", Optional: true,
			},
			"min_severity": schema.StringAttribute{
				MarkdownDescription: "Lowest severity sent: `info`, `warning` or `critical`.", Optional: true, Computed: true,
				Default:    stringdefault.StaticString("warning"),
				Validators: []validator.String{stringvalidator.OneOf("info", "warning", "critical")},
			},
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether the channel receives notifications.", Optional: true,
				Computed: true, Default: booldefault.StaticBool(true)},
		},
	}
}

func (m *channelModel) set(c *client.Channel) {
	m.ID, m.Name, m.Kind = types.StringValue(c.ID), types.StringValue(c.Name), types.StringValue(c.Kind)
	m.Config = jsontypes.NewNormalizedValue(string(c.Config))
	m.CredentialRef, m.MinSeverity, m.Enabled = optString(c.CredentialRef), types.StringValue(c.MinSeverity), types.BoolValue(c.Enabled)
}

func (r *channelResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m channelModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.CreateChannel(ctx, client.ChannelInput{Name: m.Name.ValueString(), Kind: m.Kind.ValueString(),
		Config: json.RawMessage(m.Config.ValueString()), CredentialRef: m.CredentialRef.ValueString(), MinSeverity: m.MinSeverity.ValueString()})
	if err != nil {
		apiError(&resp.Diagnostics, "create channel", err)
		return
	}
	if !m.Enabled.ValueBool() {
		if c, err = r.client.UpdateChannel(ctx, c.ID, client.ChannelPatch{Enabled: ptr(false)}); err != nil {
			apiError(&resp.Diagnostics, "disable channel", err)
			return
		}
	}
	m.set(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *channelResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m channelModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.GetChannel(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read channel", err)
		return
	}
	m.set(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *channelResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m channelModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.UpdateChannel(ctx, m.ID.ValueString(), client.ChannelPatch{Name: ptr(m.Name.ValueString()),
		Config: json.RawMessage(m.Config.ValueString()), CredentialRef: ptr(m.CredentialRef.ValueString()),
		MinSeverity: ptr(m.MinSeverity.ValueString()), Enabled: ptr(m.Enabled.ValueBool())})
	if err != nil {
		apiError(&resp.Diagnostics, "update channel", err)
		return
	}
	m.set(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *channelResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m channelModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteChannel(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete channel", err)
	}
}

func (r *channelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}
