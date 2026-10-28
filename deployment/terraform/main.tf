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

resource "aws_s3_bucket_server_side_encryption_configuration" "decoy" {
  bucket = aws_s3_bucket.decoy.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "decoy" {
  bucket  = aws_s3_bucket.decoy.id
  key     = var.decoy_key
  content = "SYNTHETIC DECOY - NOT REAL CREDENTIALS\n"
  tags = {
    purpose = "fools-gold-decoy"
  }
}

resource "aws_cloudtrail" "decoy" {
  name                          = var.trail_name
  s3_bucket_name                = var.log_bucket_name
  include_global_service_events = false
  is_multi_region_trail         = false

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

  advanced_event_selector {
    name = "Fools Gold decoy bucket listings"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
    field_selector {
      field  = "eventName"
      equals = ["ListObjects", "ListObjectsV2"]
    }
    field_selector {
      field  = "resources.ARN"
      equals = ["arn:aws-us-gov:s3:::${var.bucket_name}"]
    }
  }
}
