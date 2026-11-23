# Changelog

## 0.2.0 - 2026-11-23

### Added
- Resource `certloom_cloud_account`: AWS, Azure, Google Cloud and Cloudflare
  accounts that certloomd reads itself, with typed `aws`, `azure`, `gcp`
  and `cloudflare` blocks and a write-only `secret_wo` for stored keys.
  Needs certloom 0.1.0-rc.2 or later.
- The endpoint can also come from `CERTLOOM_SERVER`, the variable the certloom
  CLI uses.

## 0.1.0 - 2026-11-22

### Added
- Resources: `certloom_team`, `certloom_scope`, `certloom_endpoint`,
  `certloom_channel`, `certloom_issuer` (with External Account Binding),
  `certloom_dns_solver`, `certloom_template`, `certloom_policy`.
- Data sources: `certloom_team`, `certloom_scope`, `certloom_issuer`,
  `certloom_agent`.
- Write-only `eab_hmac_wo` and `secret_wo`, each with a `*_wo_version` to
  rotate; endpoint updates use `If-Match` so outside changes are not
  overwritten.
