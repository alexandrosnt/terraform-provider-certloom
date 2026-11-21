# Referencing the channel by attribute makes Terraform create it first and
# delete it last; a channel the policy names cannot be deleted.
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
