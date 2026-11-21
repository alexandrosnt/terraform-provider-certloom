resource "certloom_channel" "oncall" {
  name           = "oncall"
  kind           = "webhook"
  config         = jsonencode({ url = "https://hooks.example.com/certloom" })
  credential_ref = "env:CERTLOOM_WEBHOOK_SECRET" # read by the server, never by Terraform
  min_severity   = "warning"
}
