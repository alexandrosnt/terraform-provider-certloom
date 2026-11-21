package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"

	"github.com/alexandrosnt/certloom/client"
)

// Acceptance tests run against a real certloomd (scripts/testserver.sh) and
// only when TF_ACC is set, as terraform-plugin-testing requires.

var protoV6 = map[string]func() (tfprotov6.ProviderServer, error){
	"certloom": providerserver.NewProtocol6WithError(New("test")()),
}

func preCheck(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CERTLOOM_ENDPOINT", "CERTLOOM_TOKEN"} {
		if os.Getenv(k) == "" {
			t.Fatalf("%s must be set; start a server with scripts/testserver.sh", k)
		}
	}
}

// noSecretInState fails if any of the values appears anywhere in the
// state, which is how write-only arguments are verified end to end.
type noSecretInState struct{ secrets []string }

func (c noSecretInState) CheckState(_ context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	b, err := json.Marshal(req.State)
	if err != nil {
		resp.Error = err
		return
	}
	resp.Error = findSecret("state", string(b), c.secrets)
}

// noSecretInPlan is the same check for the plan.
type noSecretInPlan struct{ secrets []string }

func (c noSecretInPlan) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	b, err := json.Marshal(req.Plan)
	if err != nil {
		resp.Error = err
		return
	}
	resp.Error = findSecret("plan", string(b), c.secrets)
}

func findSecret(where, doc string, secrets []string) error {
	for _, s := range secrets {
		if strings.Contains(doc, s) {
			return fmt.Errorf("secret %q... found in %s", s[:4], where)
		}
	}
	return nil
}

func apiClientE() (*client.Client, error) {
	return client.New(os.Getenv("CERTLOOM_ENDPOINT"), os.Getenv("CERTLOOM_TOKEN"))
}

// secretStamp records the DNS solver's secret_updated_at on its first run and
// requires a later one on the next, proving the new secret reached the server.
type secretStamp struct {
	name string
	seen *time.Time
}

func (c secretStamp) CheckState(ctx context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	api, err := apiClientE()
	if err != nil {
		resp.Error = err
		return
	}
	s, err := api.GetDNSSolver(ctx, c.name)
	if err != nil {
		resp.Error = err
		return
	}
	switch {
	case !s.HasSecret || s.SecretUpdatedAt == nil:
		resp.Error = fmt.Errorf("solver %s has no secret", c.name)
	case c.seen.IsZero():
		*c.seen = *s.SecretUpdatedAt
	case !s.SecretUpdatedAt.After(*c.seen):
		resp.Error = fmt.Errorf("secret of %s was not replaced", c.name)
	}
}
