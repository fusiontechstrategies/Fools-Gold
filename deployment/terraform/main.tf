# Fool's Gold Terraform skeleton (NOT APPLIED BY THIS REPOSITORY)
#
# Review every value with the deploying operator. Configure the AWS provider
# for GovCloud (us-gov-west-1 or us-gov-east-1) outside this module, with an
# approved least-privilege principal. Nothing here is tested against real AWS.
#
# The decoy object is synthetic. The CloudTrail selector covers object data
# events for the exact decoy ARN plus bucket-level listings so recon trips.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "bucket_name" {
  type        = string
  description = "Dedicated private GovCloud decoy bucket"
}

variable "decoy_key" {
  type    = string
  default = "backups/inventory.txt"
}

variable "trail_name" {
  type        = string
  description = "Existing or new trail name approved for decoy data events"
}

variable "log_bucket_name" {
  type        = string
  description = "Protected CloudTrail log bucket"
}

variable "decoy_kms_key_arn" {
  type        = string
  description = "Approved customer-managed GovCloud KMS key for decoy object encryption"
}

variable "trail_kms_key_arn" {
  type        = string
  description = "Approved customer-managed KMS key whose policy permits this CloudTrail to encrypt logs"
}

variable "access_log_bucket_name" {
  type        = string
  description = "Existing protected S3 access-log destination, with a policy permitting log delivery; must differ from the decoy bucket"
}

variable "cloudwatch_log_group_arn" {
  type        = string
  description = "Existing approved CloudWatch Logs group ARN, without a trailing :*, with operator-managed encryption and retention"
}

variable "cloudwatch_logs_role_arn" {
  type        = string
  description = "Existing least-privilege role CloudTrail can assume to write to the approved CloudWatch Logs group"
}

locals {
  decoy_arn = "arn:aws-us-gov:s3:::${var.bucket_name}/${var.decoy_key}"
}

resource "aws_s3_bucket" "decoy" {
  bucket = var.bucket_name
  tags = {
    purpose = "fools-gold-decoy"
  }
}

resource "aws_s3_bucket_public_access_block" "decoy" {
  bucket                  = aws_s3_bucket.decoy.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "decoy" {
  bucket = aws_s3_bucket.decoy.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "decoy" {
  bucket        = aws_s3_bucket.decoy.id
  target_bucket = var.access_log_bucket_name
  target_prefix = "fools-gold/${var.bucket_name}/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "decoy" {
  bucket = aws_s3_bucket.decoy.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.decoy_kms_key_arn
    }
  }
}

resource "aws_s3_object" "decoy" {
  bucket  = aws_s3_bucket.decoy.id
  key     = var.decoy_key
  content = format("%s\n", "SYNTHETIC DECOY - NOT REAL CREDENTIALS")
  server_side_encryption = "aws:kms"
  kms_key_id             = var.decoy_kms_key_arn
  depends_on            = [aws_s3_bucket_versioning.decoy]
  tags = {
    purpose = "fools-gold-decoy"
  }
}

resource "aws_cloudtrail" "decoy" {
  name                          = var.trail_name
  s3_bucket_name                = var.log_bucket_name
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = var.trail_kms_key_arn
  cloud_watch_logs_group_arn    = "${var.cloudwatch_log_group_arn}:*"
  cloud_watch_logs_role_arn     = var.cloudwatch_logs_role_arn

  advanced_event_selector {
    name = "Fools Gold decoy object events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field  = "resources.ARN"
      equals = [local.decoy_arn]
    }
  }

  # Bucket-level S3 data events cover listing activity (ListObjects,
  # ListObjectsV2) and are selected by bucket resource type and ARN. This is
  # the documented way to capture recon; management selectors do not support
  # the same eventName/resource-ARN filtering shape.
  advanced_event_selector {
    name = "Fools Gold decoy bucket-level data events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Bucket"]
    }
    field_selector {
      field  = "resources.ARN"
      equals = ["arn:aws-us-gov:s3:::${var.bucket_name}"]
    }
  }
}
