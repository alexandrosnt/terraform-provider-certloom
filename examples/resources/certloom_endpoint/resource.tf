resource "certloom_endpoint" "portal" {
  host             = "portal.corp.example.com"
  scope_id         = certloom_scope.internal.id
  team_id          = certloom_team.platform.id
  interval_seconds = 3600
}
