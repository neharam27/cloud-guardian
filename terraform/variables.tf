variable "region" {
  description = "AWS region to deploy to and to scan."
  type        = string
  default     = "ap-south-1"
}

variable "alert_email" {
  description = "Email address that receives the scan reports. AWS sends a confirmation link you must click."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must look like a valid email address."
  }
}

variable "schedule_expression" {
  description = "EventBridge Scheduler expression for the daily scan."
  type        = string
  default     = "cron(30 8 * * ? *)"
}

variable "schedule_timezone" {
  description = "Timezone the schedule expression is evaluated in."
  type        = string
  default     = "Asia/Kolkata"
}

variable "min_age_days" {
  description = "Ignore unattached volumes younger than this many days."
  type        = number
  default     = 3

  validation {
    condition     = var.min_age_days >= 0
    error_message = "min_age_days must be 0 or greater."
  }
}

variable "snapshot_min_age_days" {
  description = "Only report snapshots at least this many days old."
  type        = number
  default     = 90

  validation {
    condition     = var.snapshot_min_age_days >= 0
    error_message = "snapshot_min_age_days must be 0 or greater."
  }
}

variable "stopped_min_age_days" {
  description = "Only report EC2 instances that have been stopped at least this many days."
  type        = number
  default     = 14

  validation {
    condition     = var.stopped_min_age_days >= 0
    error_message = "stopped_min_age_days must be 0 or greater."
  }
}

variable "cleanup_mode" {
  description = "dry_run: approval links only show what WOULD happen, and the executor has no permission to change anything. live: the links really back up and delete volumes."
  type        = string
  default     = "dry_run"

  validation {
    condition     = contains(["dry_run", "live"], var.cleanup_mode)
    error_message = "cleanup_mode must be \"dry_run\" or \"live\"."
  }
}

variable "digest_weekday" {
  description = "Day of the week (UTC) on which the full digest of still-open findings is emailed. 0 = Monday ... 6 = Sunday."
  type        = number
  default     = 0

  validation {
    condition     = var.digest_weekday >= 0 && var.digest_weekday <= 6
    error_message = "digest_weekday must be between 0 (Monday) and 6 (Sunday)."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the scanner Lambda."
  type        = number
  default     = 30
}
