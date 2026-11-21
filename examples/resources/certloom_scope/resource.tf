resource "certloom_scope" "internal" {
  name          = "internal"
  allow_cidrs   = ["10.20.0.0/16"]
  allow_hosts   = ["*.corp.example.com"]
  allow_private = true
  ports         = [443, 8443]
}
