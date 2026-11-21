// Package provider implements the certloom Terraform/OpenTofu provider.
package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/alexandrosnt/certloom/client"
)

type certloomProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
	CAFile   types.String `tfsdk:"ca_file"`
}

// New returns a constructor for the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &certloomProvider{version: version} }
}

func (p *certloomProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "certloom"
	resp.Version = p.version
}

func (p *certloomProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the configuration of a [certloom](https://github.com/alexandrosnt/certloom) server: " +
			"teams, probe scopes, endpoints, notification channels, ACME issuers, DNS solvers, certificate templates " +
			"and the monitoring policy. Certificates and private keys are never handled by the provider, so they " +
			"never appear in plan or state. Secrets you supply use write-only arguments (Terraform 1.11+, OpenTofu 1.11+).",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Base URL of the certloom server, for example `https://certloom.example.com:8443`. " +
					"Defaults to the `CERTLOOM_ENDPOINT` environment variable.",
				Optional: true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "API token. Defaults to the `CERTLOOM_TOKEN` environment variable. The token's role " +
					"must allow the objects you manage: `operator` covers teams and endpoints, `issuer_admin` " +
					"issuers, DNS solvers and templates, and `owner` everything, including scopes, channels and the policy.",
				Optional:  true,
				Sensitive: true,
			},
			"ca_file": schema.StringAttribute{
				MarkdownDescription: "PEM file with extra CA certificates to trust for the server's TLS certificate. " +
					"Defaults to the `CERTLOOM_CA_FILE` environment variable.",
				Optional: true,
			},
		},
	}
}

func (p *certloomProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, v := range map[string]types.String{"endpoint": m.Endpoint, "token": m.Token, "ca_file": m.CAFile} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider setting",
				"The "+name+" setting depends on a value not known until apply. Set it to a known value or use the environment variable.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	endpoint := valueOrEnv(m.Endpoint, "CERTLOOM_ENDPOINT")
	token := valueOrEnv(m.Token, "CERTLOOM_TOKEN")
	caFile := valueOrEnv(m.CAFile, "CERTLOOM_CA_FILE")
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing endpoint", "Set endpoint or CERTLOOM_ENDPOINT.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Missing token", "Set token or CERTLOOM_TOKEN.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := loadCAFile(caFile)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("ca_file"), "Cannot load CA file", err.Error())
			return
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	c, err := client.New(endpoint, token,
		client.WithHTTPClient(&http.Client{Transport: transport, Timeout: 2 * time.Minute}),
		client.WithUserAgent("terraform-provider-certloom/"+p.version))
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *certloomProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newTeamResource,
		newScopeResource,
		newEndpointResource,
		newChannelResource,
		newIssuerResource,
		newDNSSolverResource,
		newTemplateResource,
		newPolicyResource,
	}
}

func (p *certloomProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newTeamDataSource,
		newScopeDataSource,
		newIssuerDataSource,
		newAgentDataSource,
	}
}

func valueOrEnv(v types.String, env string) string {
	if !v.IsNull() {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func loadCAFile(name string) (*x509.CertPool, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no PEM certificates in %s", name)
	}
	return pool, nil
}
