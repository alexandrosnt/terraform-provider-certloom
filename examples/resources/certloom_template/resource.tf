resource "certloom_template" "public_web" {
  name     = "public-web"
  document = <<-EOT
    apiVersion: certloom/v1
    kind: CertificateTemplate
    metadata:
      name: public-web
    spec:
      issuer: ${certloom_issuer.letsencrypt.name}
      challenge: http-01
      keyAlgorithms: [ecdsa-p256]
      sans:
        allowed: ["*.example.com", "example.com"]
        maxNames: 10
  EOT
}
