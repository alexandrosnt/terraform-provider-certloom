variable "aws_secret_access_key" {
  type      = string
  sensitive = true
  ephemeral = true
}

# AWS Certificate Manager read with certloomd's own role; no secret.
resource "certloom_cloud_account" "aws_shared" {
  name = "aws-shared"
  aws = {
    regions         = ["us-east-1", "eu-west-1"]
    assume_role_arn = "arn:aws:iam::111122223333:role/certloom-read"
  }
}

# The same with a read-only access key, stored encrypted in certloom.
resource "certloom_cloud_account" "aws_prod" {
  name       = "aws-prod"
  credential = "stored"
  aws = {
    regions = ["us-east-1"]
  }
  secret_wo = jsonencode({
    access_key_id     = "AKIAIOSFODNN7EXAMPLE"
    secret_access_key = var.aws_secret_access_key
  })
  secret_wo_version = 1 # bump to rotate
}

# Azure Key Vault with certloomd's managed identity.
resource "certloom_cloud_account" "azure" {
  name = "azure-corp"
  azure = {
    vaults = ["https://corp-tls.vault.azure.net"]
  }
}
