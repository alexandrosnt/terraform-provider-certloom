terraform {
  required_version = ">= 1.11" # write-only arguments; OpenTofu 1.11+ works too
  required_providers {
    certloom = {
      source = "alexandrosnt/certloom"
    }
  }
}

# Endpoint and token can also come from CERTLOOM_ENDPOINT and CERTLOOM_TOKEN.
provider "certloom" {
  endpoint = "https://certloom.example.com:8443"
}
