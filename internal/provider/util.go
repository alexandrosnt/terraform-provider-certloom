package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

// base holds the API client for every resource and data source.
type base struct {
	client *client.Client
}

func (b *base) configure(data any, diags *diag.Diagnostics) {
	if data == nil { // provider not configured yet (validation runs)
		return
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", data))
		return
	}
	b.client = c
}

func (b *base) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	b.configure(req.ProviderData, &resp.Diagnostics)
}

// dsBase is base for data sources (the Configure signature differs).
type dsBase struct{ base }

func (b *dsBase) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	b.configure(req.ProviderData, &resp.Diagnostics)
}

// importByID is ImportState for resources whose id is their only key.
func importByID(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// readGone handles a 404 on refresh: the object was deleted outside
// Terraform, so it is dropped from state and planned again.
func readGone(ctx context.Context, err error, resp *resource.ReadResponse) bool {
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return true
	}
	return false
}

func apiError(diags *diag.Diagnostics, action string, err error) {
	diags.AddError("certloom: "+action+" failed", err.Error())
}

// optString maps "" to null so optional attributes the API leaves empty do
// not show a diff against an unset argument.
func optString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func optStringPtr(s *string) types.String {
	if s == nil {
		return types.StringNull()
	}
	return optString(*s)
}

func stringList(ctx context.Context, v []string, diags *diag.Diagnostics) types.List {
	if len(v) == 0 {
		return types.ListNull(types.StringType)
	}
	l, d := types.ListValueFrom(ctx, types.StringType, v)
	diags.Append(d...)
	return l
}

func stringSet(ctx context.Context, v []string, diags *diag.Diagnostics) types.Set {
	if len(v) == 0 {
		return types.SetNull(types.StringType)
	}
	s, d := types.SetValueFrom(ctx, types.StringType, v)
	diags.Append(d...)
	return s
}

func listStrings(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	var out []string
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	diags.Append(l.ElementsAs(ctx, &out, false)...)
	return out
}

func setStrings(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	var out []string
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	diags.Append(s.ElementsAs(ctx, &out, false)...)
	return out
}

func ptr[T any](v T) *T { return &v }

var httpsURL = regexp.MustCompile(`^https://[^\s/]+`)

// mustBeTrue rejects anything but true, for explicit acknowledgements.
type mustBeTrue struct{}

func (mustBeTrue) Description(context.Context) string         { return "value must be true" }
func (mustBeTrue) MarkdownDescription(context.Context) string { return "value must be `true`" }

func (mustBeTrue) ValidateBool(_ context.Context, req validator.BoolRequest, resp *validator.BoolResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueBool() {
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Terms of service not accepted",
		"agree_tos must be true: certloom only uses a CA whose terms of service you have accepted.")
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
