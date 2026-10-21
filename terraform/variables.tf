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

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the scanner Lambda."
  type        = number
  default     = 30
}
