# Changelog

## Unreleased

### Added
- Resources: `certloom_team`, `certloom_scope`, `certloom_endpoint`,
  `certloom_channel`, `certloom_issuer` (with External Account Binding),
  `certloom_dns_solver`, `certloom_template`, `certloom_policy`.
- Data sources: `certloom_team`, `certloom_scope`, `certloom_issuer`,
  `certloom_agent`.
- Write-only `eab_hmac_wo` and `secret_wo`, each with a `*_wo_version` to
  rotate; endpoint updates use `If-Match` so outside changes are not
  overwritten.
