package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAccTeamScopeEndpoint(t *testing.T) {
	n := acctest.RandomWithPrefix("acc")
	config := func(team string, interval int, enabled bool) string {
		return fmt.Sprintf(`
resource "certloom_team" "sre" {
  name    = %[1]q
  contact = "sre@example.test"
}

resource "certloom_scope" "lab" {
  name           = "%[2]s-lab"
  allow_cidrs    = ["127.0.0.0/8"]
  allow_loopback = true
  ports          = [8443, 9443]
}

resource "certloom_endpoint" "local" {
  host             = "127.0.0.1"
  port             = 8443
  sni              = "%[2]s.example.test"
  scope_id         = certloom_scope.lab.id
  team_id          = certloom_team.sre.id
  interval_seconds = %[3]d
  enabled          = %[4]t
}

data "certloom_team" "sre" {
  name = certloom_team.sre.name
}
`, team, n, interval, enabled)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: protoV6,
		CheckDestroy:             endpointsGone,
		Steps: []resource.TestStep{
			{
				Config: config(n+"-sre", 3600, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("certloom_endpoint.local", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("certloom_endpoint.local", tfjsonpath.New("version"), knownvalue.Int64Exact(2)),
					statecheck.ExpectKnownValue("certloom_scope.lab", tfjsonpath.New("allow_private"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("data.certloom_team.sre", tfjsonpath.New("contact"), knownvalue.StringExact("sre@example.test")),
				},
			},
			{
				// Renaming the team and changing settings updates in place.
				Config: config(n+"-platform", 900, true),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("certloom_team.sre", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction("certloom_endpoint.local", plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("certloom_endpoint.local", tfjsonpath.New("interval_seconds"), knownvalue.Int64Exact(900)),
					statecheck.ExpectKnownValue("certloom_endpoint.local", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
				},
			},
			{ResourceName: "certloom_endpoint.local", ImportState: true, ImportStateVerify: true},
			{ResourceName: "certloom_scope.lab", ImportState: true, ImportStateVerify: true},
			{ResourceName: "certloom_team.sre", ImportState: true, ImportStateVerify: true},
		},
	})
}

func endpointsGone(s *terraform.State) error {
	c, err := apiClientE()
	if err != nil {
		return err
	}
	for _, r := range s.RootModule().Resources {
		if r.Type != "certloom_endpoint" {
			continue
		}
		if _, err := c.GetEndpoint(context.Background(), r.Primary.ID); err == nil {
			return fmt.Errorf("endpoint %s still exists", r.Primary.ID)
		}
	}
	return nil
}

func TestAccChannelAndPolicy(t *testing.T) {
	n := acctest.RandomWithPrefix("acc")
	config := func(severity string) string {
		return fmt.Sprintf(`
resource "certloom_channel" "oncall" {
  name           = %[1]q
  kind           = "webhook"
  config         = jsonencode({ url = "https://hooks.example.test/%[1]s" })
  credential_ref = "env:CERTLOOM_WEBHOOK_SECRET"
  min_severity   = %[2]q
}

# Naming the channel through its attribute orders creation and destruction:
# a channel the policy names cannot be deleted first.
resource "certloom_policy" "this" {
  document = <<-EOT
    apiVersion: certloom/v1
    kind: MonitoringPolicy
    spec:
      escalation:
        after: 4h
        channels: [${certloom_channel.oncall.name}]
  EOT
}
`, n, severity)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: protoV6,
		Steps: []resource.TestStep{
			{
				Config: config("warning"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("certloom_channel.oncall", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("certloom_policy.this", tfjsonpath.New("id"), knownvalue.StringExact("policy")),
				},
			},
			{
				Config: config("critical"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("certloom_channel.oncall", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction("certloom_policy.this", plancheck.ResourceActionNoop),
				}},
			},
			{ResourceName: "certloom_channel.oncall", ImportState: true, ImportStateVerify: true},
			{ResourceName: "certloom_policy.this", ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestAccIssuerEABAndTemplate(t *testing.T) {
	n := acctest.RandomWithPrefix("acc")
	hmac1 := "c2VjcmV0LWhtYWMtb25lLW5vdC1yZWFs" + acctest.RandString(8)
	hmac2 := "c2VjcmV0LWhtYWMtdHdvLW5vdC1yZWFs" + acctest.RandString(8)
	config := func(version int, email string) string {
		return fmt.Sprintf(`
# Secrets come in through ephemeral variables, which Terraform keeps out of
# plan and state, so the checks below can scan both whole.
variable "eab_hmac" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "certloom_issuer" "ca" {
  name                = %[1]q
  directory_url       = "https://acme.example.test/directory"
  agree_tos           = true
  email               = %[3]q
  eab_mode            = "reusable"
  eab_kid             = "kid-1"
  eab_hmac_wo         = var.eab_hmac
  eab_hmac_wo_version = %[2]d
}

resource "certloom_template" "web" {
  name     = "%[1]s-web"
  document = <<-EOT
    apiVersion: certloom/v1
    kind: CertificateTemplate
    metadata:
      name: %[1]s-web
    spec:
      issuer: ${certloom_issuer.ca.name}
      challenge: http-01
      keyAlgorithms: [ecdsa-p256]
      sans:
        allowed: ["*.example.test"]
        maxNames: 5
  EOT
}

data "certloom_issuer" "ca" {
  name = certloom_issuer.ca.name
}
`, n, version, email)
	}
	secrets := []string{hmac1, hmac2}
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: protoV6,
		Steps: []resource.TestStep{
			{
				Config:           config(1, "pki@example.test"),
				ConfigVariables:  hmacVar(hmac1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{noSecretInPlan{secrets}}},
				ConfigStateChecks: []statecheck.StateCheck{
					noSecretInState{secrets},
					statecheck.ExpectKnownValue("certloom_issuer.ca", tfjsonpath.New("eab_hmac_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue("data.certloom_issuer.ca", tfjsonpath.New("eab_mode"), knownvalue.StringExact("reusable")),
					statecheck.ExpectKnownValue("certloom_template.web", tfjsonpath.New("version"), knownvalue.Int64Exact(1)),
				},
			},
			{
				// A new HMAC with the same version is not sent: write-only
				// values cannot be compared, so the version is the trigger.
				Config:          config(1, "pki@example.test"),
				ConfigVariables: hmacVar(hmac2),
				PlanOnly:        true,
			},
			{
				Config:          config(2, "security@example.test"),
				ConfigVariables: hmacVar(hmac2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					noSecretInPlan{secrets},
					plancheck.ExpectResourceAction("certloom_issuer.ca", plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{noSecretInState{secrets}},
			},
			{
				ResourceName: "certloom_issuer.ca", ImportState: true, ImportStateVerify: true, ConfigVariables: hmacVar(hmac2),
				ImportStateVerifyIgnore: []string{"eab_hmac_wo_version"},
			},
			{ResourceName: "certloom_template.web", ImportState: true, ImportStateVerify: true, ConfigVariables: hmacVar(hmac2)},
		},
	})
}

func TestAccDNSSolverSecret(t *testing.T) {
	n := acctest.RandomWithPrefix("acc")
	tok1 := "cf-token-one-" + acctest.RandString(16)
	tok2 := "cf-token-two-" + acctest.RandString(16)
	config := func(version int) string {
		return fmt.Sprintf(`
variable "cf_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "certloom_dns_solver" "cf" {
  name              = %[1]q
  provider_type     = "cloudflare"
  zones             = ["example.test"]
  credential        = "stored"
  secret_wo         = jsonencode({ api_token = var.cf_token })
  secret_wo_version = %[2]d
}
`, n, version)
	}
	secrets := []string{tok1, tok2}
	stamp := secretStamp{name: n, seen: new(time.Time)}
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: protoV6,
		Steps: []resource.TestStep{
			{
				Config:           config(1),
				ConfigVariables:  tokenVar(tok1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{noSecretInPlan{secrets}}},
				ConfigStateChecks: []statecheck.StateCheck{
					noSecretInState{secrets},
					statecheck.ExpectKnownValue("certloom_dns_solver.cf", tfjsonpath.New("secret_wo"), knownvalue.Null()),
					stamp,
				},
			},
			{
				Config:          config(2),
				ConfigVariables: tokenVar(tok2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					noSecretInPlan{secrets},
					plancheck.ExpectResourceAction("certloom_dns_solver.cf", plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{noSecretInState{secrets}, stamp},
			},
			{
				ResourceName: "certloom_dns_solver.cf", ImportState: true, ImportStateVerify: true, ConfigVariables: tokenVar(tok2),
				ImportStateVerifyIgnore: []string{"secret_wo_version"},
			},
		},
	})
}

func hmacVar(v string) config.Variables {
	return config.Variables{"eab_hmac": config.StringVariable(v)}
}
func tokenVar(v string) config.Variables {
	return config.Variables{"cf_token": config.StringVariable(v)}
}
