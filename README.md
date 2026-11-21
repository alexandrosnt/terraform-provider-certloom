# Terraform provider for certloom

Manages the configuration of a [certloom](https://github.com/alexandrosnt/certloom)
server with Terraform or OpenTofu: teams, probe scopes, endpoints, notification
channels, ACME issuers, DNS-01 solvers, certificate templates and the monitoring
policy.

The provider never handles certificates or private keys; those stay with the
certloom agents. Secrets you supply (DNS provider credentials, EAB HMAC keys) go
through write-only arguments, so nothing secret is written to plan or state.

## Requirements

- Terraform 1.11 or later, or OpenTofu 1.11 or later (write-only arguments)
- A certloom server and an API token whose role can manage the objects you
  declare: `operator` for teams and endpoints, `issuer_admin` for issuers,
  DNS solvers and templates, `owner` for everything including scopes,
  channels and the policy

## Usage

```hcl
terraform {
  required_providers {
    certloom = {
      source = "alexandrosnt/certloom"
    }
  }
}

provider "certloom" {
  endpoint = "https://certloom.example.com:8443"
  # token from CERTLOOM_TOKEN
}

resource "certloom_scope" "internal" {
  name          = "internal"
  allow_cidrs   = ["10.20.0.0/16"]
  allow_private = true
}

resource "certloom_endpoint" "portal" {
  host     = "portal.corp.example.com"
  scope_id = certloom_scope.internal.id
}
```

Pass secrets in `ephemeral` variables so they stay out of the plan as well:

```hcl
variable "cloudflare_api_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "certloom_dns_solver" "cloudflare" {
  name              = "cloudflare"
  provider_type     = "cloudflare"
  zones             = ["example.com"]
  credential        = "stored"
  secret_wo         = jsonencode({ api_token = var.cloudflare_api_token })
  secret_wo_version = 1 # bump to rotate
}
```

See [docs/](docs/) for every resource and data source.

## Development

```sh
go build ./...
make lint

# Acceptance tests need Docker and a certloom checkout.
CERTLOOM_SRC=../certloom scripts/testserver.sh start
. .testserver/env
make testacc                                     # terraform from PATH
TF_ACC_TERRAFORM_PATH=$(command -v tofu) make testacc
scripts/testserver.sh stop

make docs   # regenerate docs/ after schema or example changes
```

Every acceptance test that uses a secret also scans the full plan and state for
it and fails if it is found.

Commits need a `Signed-off-by` line (`git commit -s`), as in certloom.

## License

Apache License 2.0. See [LICENSE](LICENSE).
