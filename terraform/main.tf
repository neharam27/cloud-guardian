locals {
  name = "cloud-guardian"
}

# --- Lambda package ------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/lambda.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

# --- Notifications -------------------------------------------------------------

resource "aws_sns_topic" "reports" {
  name              = "${local.name}-reports"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.reports.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Findings history ----------------------------------------------------------

# One item per finding (see src/findings_store.py). On-demand billing means no
# capacity to manage and no cost while idle.
resource "aws_dynamodb_table" "findings" {
  # checkov:skip=CKV_AWS_28:Point-in-time recovery is skipped on purpose. The data is derived from AWS state and rebuilt by the next scan; losing the table only restarts first_seen history.
  # checkov:skip=CKV_AWS_119:Encrypted at rest with the default AWS-owned key. A customer-managed KMS key adds cost and key-policy complexity for non-sensitive scan metadata.
  name         = "${local.name}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  # Lets the scanner list every open finding without scanning the whole table.
  global_secondary_index {
    name            = "by-status"
    hash_key        = "status"
    projection_type = "ALL"
  }
}

# --- Scanner Lambda ------------------------------------------------------------

# Created explicitly so retention is bounded (otherwise logs are kept forever).
resource "aws_cloudwatch_log_group" "scanner" {
  # checkov:skip=CKV_AWS_158:Default CloudWatch encryption is enough for scan logs here; a customer-managed key adds cost and complexity.
  # checkov:skip=CKV_AWS_338:These are operational scan logs, not audit logs. 30 days (configurable) keeps storage near zero.
  name              = "/aws/lambda/${local.name}-scanner"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "scanner" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scanner.arn}:*"]
  }

  # Describe* calls do not support resource-level permissions, so "*" is required.
  # These are the ONLY EC2 permissions the scanner has, and all are read-only.
  statement {
    sid = "ReadEc2Inventory"
    actions = [
      "ec2:DescribeVolumes",
      "ec2:DescribeAddresses",
      "ec2:DescribeSnapshots",
      "ec2:DescribeImages",
      "ec2:DescribeInstances",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PublishReport"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.reports.arn]
  }

  # Findings history: the one table and its status index, nothing else. No Delete,
  # no Scan, no table-level actions.
  statement {
    sid = "FindingsHistory"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
    ]
    resources = [
      aws_dynamodb_table.findings.arn,
      "${aws_dynamodb_table.findings.arn}/index/by-status",
    ]
  }

  # Required because tracing is enabled on the function. These actions cannot be scoped.
  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "scanner" {
  name               = "${local.name}-scanner"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "scanner" {
  name   = "scanner-least-privilege"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner.json
}

resource "aws_lambda_function" "scanner" {
  # checkov:skip=CKV_AWS_117:Function needs no VPC access; it only calls public AWS APIs. A VPC would require a NAT gateway or endpoints, which cost money.
  # checkov:skip=CKV_AWS_116:No dead-letter queue yet; failures are visible in CloudWatch Logs and the scheduler retries. Revisit in week 3.
  # checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low concurrency limits. One invocation per day, so concurrency is not a risk.
  # checkov:skip=CKV_AWS_173:Environment variables hold no secrets (an SNS topic ARN and a number).
  # checkov:skip=CKV_AWS_272:Code signing is out of scope for this project.
  function_name = "${local.name}-scanner"
  description   = "Read-only scan for wasted EBS volumes, Elastic IPs, snapshots and long-stopped instances; tracks findings in DynamoDB and emails what changed."

  role             = aws_iam_role.scanner.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  timeout     = 60
  memory_size = 128

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.reports.arn
      MIN_AGE_DAYS          = tostring(var.min_age_days)
      SNAPSHOT_MIN_AGE_DAYS = tostring(var.snapshot_min_age_days)
      STOPPED_MIN_AGE_DAYS  = tostring(var.stopped_min_age_days)
      FINDINGS_TABLE        = aws_dynamodb_table.findings.name
      DIGEST_WEEKDAY        = tostring(var.digest_weekday)
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.scanner,
    aws_iam_role_policy.scanner,
  ]
}

# --- Daily schedule ------------------------------------------------------------

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "scheduler_invoke" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.scanner.arn]
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "invoke-scanner"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_invoke.json
}

resource "aws_scheduler_schedule" "daily_scan" {
  # checkov:skip=CKV_AWS_297:The schedule payload is a constant with no sensitive data; a customer-managed KMS key adds cost for no benefit.
  name        = "${local.name}-daily"
  description = "Runs the scanner once a day."

  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.scanner.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ source = "scheduler" })

    retry_policy {
      maximum_retry_attempts = 2
    }
  }
}
