terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Partial configuration: the bucket and region come from backend.hcl
  # (see backend.hcl.example). use_lockfile gives S3-native state locking,
  # so no DynamoDB lock table is needed.
  backend "s3" {
    key          = "cloud-guardian/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project    = "cloud-guardian"
      managed-by = "terraform"
    }
  }
}
