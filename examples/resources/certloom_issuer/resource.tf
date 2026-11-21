resource "certloom_issuer" "letsencrypt" {
  name          = "letsencrypt"
  directory_url = "https://acme-v02.api.letsencrypt.org/directory"
  email         = "pki@example.com"
  agree_tos     = true
}

# A CA that requires External Account Binding. The HMAC is write-only and
# comes from an ephemeral variable, so it is in neither plan nor state.
variable "zerossl_eab_hmac" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "certloom_issuer" "zerossl" {
  name                = "zerossl"
  directory_url       = "https://acme.zerossl.com/v2/DV90"
  email               = "pki@example.com"
  agree_tos           = true
  eab_mode            = "reusable"
  eab_kid             = "your-eab-kid"
  eab_hmac_wo         = var.zerossl_eab_hmac
  eab_hmac_wo_version = 1 # bump to send a new HMAC
}
