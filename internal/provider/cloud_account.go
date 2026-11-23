package provider

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type cloudAccountResource struct{ base }

type awsSettings struct {
	Regions       types.List   `tfsdk:"regions"`
	AssumeRoleARN types.String `tfsdk:"assume_role_arn"`
	ExternalID    types.String `tfsdk:"external_id"`
	PrivateCA     types.Bool   `tfsdk:"private_ca"`
}

type azureSettings struct {
	Vaults   types.List   `tfsdk:"vaults"`
	TenantID types.String `tfsdk:"tenant_id"`
	ClientID types.String `tfsdk:"client_id"`
}

type gcpSettings struct {
	Project            types.String `tfsdk:"project"`
	Locations          types.List   `tfsdk:"locations"`
	CertificateManager types.Bool   `tfsdk:"certificate_manager"`
	CAS                types.Bool   `tfsdk:"cas"`
}

type cloudflareSettings struct {
	Zones    types.List `tfsdk:"zones"`
	OriginCA types.Bool `tfsdk:"origin_ca"`
}

type cloudAccountModel struct {
	ID              types.String        `tfsdk:"id"`
	Name            types.String        `tfsdk:"name"`
	Credential      types.String        `tfsdk:"credential"`
	IntervalSeconds types.Int64         `tfsdk:"interval_seconds"`
	AWS             *awsSettings        `tfsdk:"aws"`
	Azure           *azureSettings      `tfsdk:"azure"`
	GCP             *gcpSettings        `tfsdk:"gcp"`
	Cloudflare      *cloudflareSettings `tfsdk:"cloudflare"`
	SecretWO        types.String        `tfsdk:"secret_wo"`
	SecretWOVersion types.Int64         `tfsdk:"secret_wo_version"`
}

func newCloudAccountResource() resource.Resource { return &cloudAccountResource{} }

func (r *cloudAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_account"
}

// switchedProvider replaces the account when a provider block appears or
// goes away; the provider of an account never changes in place.
var switchedProvider = objectplanmodifier.RequiresReplaceIf(
	func(_ context.Context, req planmodifier.ObjectRequest, resp *objectplanmodifier.RequiresReplaceIfFuncResponse) {
		resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
	}, "Changing the cloud provider replaces the account.", "Changing the cloud provider replaces the account.")

func (r *cloudAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nonEmpty := []validator.List{listvalidator.SizeAtLeast(1)}
	optBool := func(desc string) schema.BoolAttribute {
		return schema.BoolAttribute{MarkdownDescription: desc, Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
	}
	block := func(desc string, attrs map[string]schema.Attribute) schema.SingleNestedAttribute {
		return schema.SingleNestedAttribute{MarkdownDescription: desc, Optional: true, Attributes: attrs,
			PlanModifiers: []planmodifier.Object{switchedProvider}}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A cloud account that certloomd reads itself, read-only, without an agent: AWS Certificate Manager " +
			"and Private CA, Azure Key Vault, Google Certificate Manager and CA Service, or Cloudflare. Its certificates join the " +
			"inventory and get the usual checks. Set exactly one of `aws`, `azure`, `gcp` or `cloudflare`.\n\n" +
			"With `credential = \"ambient\"` (the default) certloomd uses its own cloud identity: an instance or task role, " +
			"workload identity, a managed identity or Application Default Credentials. With `credential = \"stored\"` the " +
			"credential is passed in the write-only `secret_wo`; certloom keeps it encrypted, and it is never written to " +
			"plan or state or returned by the API. Bump `secret_wo_version` to rotate it.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute(),
			"name": schema.StringAttribute{MarkdownDescription: "Unique account name.", Required: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.RegexMatches(cloudAccountName, "1-64 letters, digits, '.', '_' or '-'")}},
			"credential": schema.StringAttribute{
				MarkdownDescription: "`ambient` (certloomd's own cloud identity) or `stored` (the secret in `secret_wo`). Cloudflare needs `stored`.",
				Optional:            true, Computed: true, Default: stringdefault.StaticString("ambient"),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.OneOf("ambient", "stored")},
			},
			"interval_seconds": schema.Int64Attribute{MarkdownDescription: "Seconds between scans; at least 300.",
				Optional: true, Computed: true, Default: int64default.StaticInt64(3600),
				Validators: []validator.Int64{int64validator.AtLeast(300)}},
			"aws": block("AWS Certificate Manager (and optionally Private CA) in the listed regions.", map[string]schema.Attribute{
				"regions": schema.ListAttribute{MarkdownDescription: "Regions to read, e.g. `[\"us-east-1\"]`.",
					ElementType: types.StringType, Required: true, Validators: nonEmpty},
				"assume_role_arn": schema.StringAttribute{MarkdownDescription: "Role to assume in this account.", Optional: true},
				"external_id":     schema.StringAttribute{MarkdownDescription: "External id the role's trust policy requires.", Optional: true},
				"private_ca":      optBool("Also list AWS Private CA authorities."),
			}),
			"azure": block("Azure Key Vault certificates.", map[string]schema.Attribute{
				"vaults": schema.ListAttribute{MarkdownDescription: "Vault URLs, e.g. `[\"https://corp-tls.vault.azure.net\"]`.",
					ElementType: types.StringType, Required: true, Validators: nonEmpty},
				"tenant_id": schema.StringAttribute{MarkdownDescription: "Tenant of the service principal (required with a stored secret).", Optional: true},
				"client_id": schema.StringAttribute{MarkdownDescription: "Application (client) id of the service principal (required with a stored secret).", Optional: true},
			}),
			"gcp": block("Google Certificate Manager (and optionally CA Service) in one project.", map[string]schema.Attribute{
				"project": schema.StringAttribute{MarkdownDescription: "Project id.", Required: true},
				"locations": schema.ListAttribute{MarkdownDescription: "Locations; default `[\"global\"]`.",
					ElementType: types.StringType, Optional: true, Validators: nonEmpty},
				"certificate_manager": schema.BoolAttribute{MarkdownDescription: "Read Certificate Manager (default true).",
					Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
				"cas": optBool("Also list CA Service authorities."),
			}),
			"cloudflare": block("Cloudflare edge certificates (and optionally Origin CA certificates).", map[string]schema.Attribute{
				"zones": schema.ListAttribute{MarkdownDescription: "Zone names; default every zone the token can see.",
					ElementType: types.StringType, Optional: true, Validators: nonEmpty},
				"origin_ca": optBool("Also list Origin CA certificates."),
			}),
			"secret_wo": schema.StringAttribute{
				MarkdownDescription: "Credential as a JSON object of strings. AWS: `jsonencode({access_key_id = ..., secret_access_key = ...})`; " +
					"Azure: `jsonencode({client_secret = ...})`; Google: `jsonencode({service_account_key = file(\"key.json\")})`; " +
					"Cloudflare: `jsonencode({api_token = var.cloudflare_token})`. Write-only: never stored in plan or state. " +
					"Required on create when `credential` is `stored`.",
				Optional: true, Sensitive: true, WriteOnly: true,
				Validators: []validator.String{stringvalidator.AlsoRequires(path.MatchRoot("secret_wo_version"))},
			},
			"secret_wo_version": schema.Int64Attribute{
				MarkdownDescription: "Change this number to send a new `secret_wo`.",
				Optional:            true, Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
		},
	}
}

func (r *cloudAccountResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{resourcevalidator.ExactlyOneOf(path.MatchRoot("aws"), path.MatchRoot("azure"),
		path.MatchRoot("gcp"), path.MatchRoot("cloudflare"))}
}

// apiSettings returns the provider name and the settings object the API takes.
func (m *cloudAccountModel) apiSettings(ctx context.Context, diags *diag.Diagnostics) (string, json.RawMessage) {
	var provider string
	var v any
	switch {
	case m.AWS != nil:
		provider = "aws"
		v = map[string]any{"regions": listStrings(ctx, m.AWS.Regions, diags), "assume_role_arn": m.AWS.AssumeRoleARN.ValueString(),
			"external_id": m.AWS.ExternalID.ValueString(), "private_ca": m.AWS.PrivateCA.ValueBool()}
	case m.Azure != nil:
		provider = "azure"
		v = map[string]any{"vaults": listStrings(ctx, m.Azure.Vaults, diags), "tenant_id": m.Azure.TenantID.ValueString(),
			"client_id": m.Azure.ClientID.ValueString()}
	case m.GCP != nil:
		provider = "gcp"
		s := map[string]any{"project": m.GCP.Project.ValueString(), "cas": m.GCP.CAS.ValueBool(),
			"certificate_manager": m.GCP.CertificateManager.ValueBool()}
		if !m.GCP.Locations.IsNull() {
			s["locations"] = listStrings(ctx, m.GCP.Locations, diags)
		}
		v = s
	case m.Cloudflare != nil:
		provider = "cloudflare"
		s := map[string]any{"origin_ca": m.Cloudflare.OriginCA.ValueBool()}
		if !m.Cloudflare.Zones.IsNull() {
			s["zones"] = listStrings(ctx, m.Cloudflare.Zones, diags)
		}
		v = s
	}
	b, err := json.Marshal(v)
	if err != nil {
		diags.AddError("Cannot encode cloud account settings", err.Error())
	}
	return provider, b
}

func (m *cloudAccountModel) set(ctx context.Context, a *client.CloudAccount, diags *diag.Diagnostics) {
	m.ID, m.Name, m.Credential = types.StringValue(a.ID), types.StringValue(a.Name), types.StringValue(a.Credential)
	m.IntervalSeconds = types.Int64Value(int64(a.IntervalSeconds))
	m.AWS, m.Azure, m.GCP, m.Cloudflare = nil, nil, nil, nil
	var s struct {
		Regions            []string `json:"regions"`
		AssumeRoleARN      string   `json:"assume_role_arn"`
		ExternalID         string   `json:"external_id"`
		PrivateCA          bool     `json:"private_ca"`
		Vaults             []string `json:"vaults"`
		TenantID           string   `json:"tenant_id"`
		ClientID           string   `json:"client_id"`
		Project            string   `json:"project"`
		Locations          []string `json:"locations"`
		CertificateManager *bool    `json:"certificate_manager"`
		CAS                bool     `json:"cas"`
		Zones              []string `json:"zones"`
		OriginCA           bool     `json:"origin_ca"`
	}
	if err := json.Unmarshal(a.Settings, &s); err != nil {
		diags.AddError("Cannot read cloud account settings", err.Error())
		return
	}
	list := func(v []string) types.List {
		if len(v) == 0 {
			return types.ListNull(types.StringType)
		}
		return stringList(ctx, v, diags)
	}
	switch a.Provider {
	case "aws":
		m.AWS = &awsSettings{Regions: list(s.Regions), AssumeRoleARN: optString(s.AssumeRoleARN),
			ExternalID: optString(s.ExternalID), PrivateCA: types.BoolValue(s.PrivateCA)}
	case "azure":
		m.Azure = &azureSettings{Vaults: list(s.Vaults), TenantID: optString(s.TenantID), ClientID: optString(s.ClientID)}
	case "gcp":
		m.GCP = &gcpSettings{Project: types.StringValue(s.Project), Locations: list(s.Locations),
			CertificateManager: types.BoolValue(s.CertificateManager == nil || *s.CertificateManager), CAS: types.BoolValue(s.CAS)}
	case "cloudflare":
		m.Cloudflare = &cloudflareSettings{Zones: list(s.Zones), OriginCA: types.BoolValue(s.OriginCA)}
	}
	m.SecretWO = types.StringNull()
}

func (r *cloudAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m, cfg cloudAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	provider, settings := m.apiSettings(ctx, &resp.Diagnostics)
	in := client.CloudAccountInput{Name: m.Name.ValueString(), Provider: provider, Credential: m.Credential.ValueString(),
		Settings: settings, IntervalSeconds: int(m.IntervalSeconds.ValueInt64())}
	if !cfg.SecretWO.IsNull() {
		in.Secret = json.RawMessage(cfg.SecretWO.ValueString())
	}
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.CreateCloudAccount(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "create cloud account", err)
		return
	}
	version := m.SecretWOVersion
	m.set(ctx, a, &resp.Diagnostics)
	m.SecretWOVersion = version
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *cloudAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m cloudAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.GetCloudAccount(ctx, m.ID.ValueString())
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read cloud account", err)
		return
	}
	m.set(ctx, a, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *cloudAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, cfg cloudAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	_, settings := plan.apiSettings(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.UpdateCloudAccount(ctx, id, client.CloudAccountPatch{Settings: settings,
		IntervalSeconds: int(plan.IntervalSeconds.ValueInt64())}, 0)
	if err != nil {
		apiError(&resp.Diagnostics, "update cloud account", err)
		return
	}
	if !plan.SecretWOVersion.Equal(state.SecretWOVersion) && !cfg.SecretWO.IsNull() {
		if err := r.client.SetCloudAccountSecret(ctx, id, json.RawMessage(cfg.SecretWO.ValueString())); err != nil {
			apiError(&resp.Diagnostics, "set cloud account secret", err)
			return
		}
	}
	version := plan.SecretWOVersion
	plan.set(ctx, a, &resp.Diagnostics)
	plan.SecretWOVersion = version
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m cloudAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteCloudAccount(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete cloud account", err)
	}
}

func (r *cloudAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

var cloudAccountName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
