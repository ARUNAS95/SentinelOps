terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    kms            = "http://moto:5000"
    secretsmanager = "http://moto:5000"
    sts            = "http://moto:5000"
  }
}

resource "aws_kms_key" "demo" {
  description             = "SentinelOps local demo key; not for production"
  deletion_window_in_days = 7
  enable_key_rotation     = false
  tags = {
    Project     = "SentinelOps"
    Environment = "local-demo"
  }
}

resource "aws_kms_alias" "demo" {
  name          = "alias/sentinelops-local-demo"
  target_key_id = aws_kms_key.demo.key_id
}

resource "aws_secretsmanager_secret" "demo" {
  name                    = "sentinelops/local-demo"
  description             = "Dummy secret for local development only"
  kms_key_id              = aws_kms_key.demo.arn
  recovery_window_in_days = 0
  tags = {
    Project     = "SentinelOps"
    Environment = "local-demo"
  }
}

resource "aws_secretsmanager_secret_version" "demo" {
  secret_id = aws_secretsmanager_secret.demo.id
  secret_string = jsonencode({
    api_key = "demo-not-a-real-credential"
    purpose = "Local emulator test value only"
  })
}
