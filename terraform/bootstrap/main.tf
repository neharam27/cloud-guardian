# Bootstrap: creates the S3 bucket that stores Terraform state for the main stack.
# Run this ONCE with local state, then never touch it again.
#
#   cd terraform/bootstrap
#   terraform init
#   terraform apply
#
# This stack's own state stays local (terraform.tfstate, git-ignored). That is fine
# for a one-resource bootstrap.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "region" {
  description = "AWS region for the state bucket (use the same one as the main stack)."
  type        = string
  default     = "ap-south-1"
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

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "cloud-guardian-tfstate-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "state" {
  # checkov:skip=CKV_AWS_18:Access logging needs a second bucket; overkill for a single-user state bucket.
  # checkov:skip=CKV_AWS_144:Cross-region replication doubles storage and adds IAM complexity; state is versioned and re-creatable.
  # checkov:skip=CKV_AWS_145:SSE-S3 (AES256) encryption is enabled; a customer-managed KMS key adds cost and key-policy complexity.
  # checkov:skip=CKV2_AWS_62:No consumers need event notifications from the state bucket.
  bucket = local.bucket_name

  # Losing state is painful. Remove this block deliberately if you want to tear down.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.tls_only.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

output "state_bucket" {
  description = "Put this in terraform/backend.hcl"
  value       = aws_s3_bucket.state.bucket
}
