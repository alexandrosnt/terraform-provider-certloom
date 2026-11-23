package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAccCloudAccount(t *testing.T) {
	n := acctest.RandomWithPrefix("acc")
	tok1 := "cf-token-one-" + acctest.RandString(16)
	tok2 := "cf-token-two-" + acctest.RandString(16)
	config := func(regions string, version int) string {
		return fmt.Sprintf(`
variable "cf_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "certloom_cloud_account" "aws" {
  name = "%[1]s-aws"
  aws = {
    regions = %[2]s
  }
}

resource "certloom_cloud_account" "cf" {
  name              = "%[1]s-cf"
  credential        = "stored"
  cloudflare        = { zones = ["example.test"], origin_ca = true }
  secret_wo         = jsonencode({ api_token = var.cf_token })
  secret_wo_version = %[3]d
}
`, n, regions, version)
	}
	secrets := []string{tok1, tok2}
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: protoV6,
		Steps: []resource.TestStep{
			{
				Config:           config(`["us-east-1"]`, 1),
				ConfigVariables:  tokenVar(tok1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{noSecretInPlan{secrets}}},
				ConfigStateChecks: []statecheck.StateCheck{
					noSecretInState{secrets},
					statecheck.ExpectKnownValue("certloom_cloud_account.aws", tfjsonpath.New("credential"), knownvalue.StringExact("ambient")),
					statecheck.ExpectKnownValue("certloom_cloud_account.aws", tfjsonpath.New("aws").AtMapKey("private_ca"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("certloom_cloud_account.cf", tfjsonpath.New("secret_wo"), knownvalue.Null()),
				},
			},
			{
				// Order is kept as written, so a second plan is empty.
				Config:          config(`["us-east-1", "eu-west-1"]`, 2),
				ConfigVariables: tokenVar(tok2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					noSecretInPlan{secrets},
					plancheck.ExpectResourceAction("certloom_cloud_account.aws", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction("certloom_cloud_account.cf", plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{noSecretInState{secrets}},
			},
			{
				ResourceName: "certloom_cloud_account.aws", ImportState: true, ImportStateVerify: true, ConfigVariables: tokenVar(tok2),
			},
			{
				ResourceName: "certloom_cloud_account.cf", ImportState: true, ImportStateVerify: true, ConfigVariables: tokenVar(tok2),
				ImportStateVerifyIgnore: []string{"secret_wo_version"},
			},
		},
	})
}
