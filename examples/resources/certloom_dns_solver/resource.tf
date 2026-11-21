variable "cloudflare_api_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

data "certloom_agent" "web01" {
  name = "web-01"
}

resource "certloom_dns_solver" "cloudflare" {
  name              = "cloudflare"
  provider_type     = "cloudflare"
  zones             = ["example.com"]
  credential        = "stored"
  secret_wo         = jsonencode({ api_token = var.cloudflare_api_token })
  secret_wo_version = 1 # bump to rotate
  agent_ids         = [data.certloom_agent.web01.id]
}
