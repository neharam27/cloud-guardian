# --- Approval-gated clean-up -----------------------------------------------------
#
# Three pieces, each with the least power it can have:
#
#   scanner   (main.tf)  can CREATE approvals. It cannot approve or act.
#   approver             public URL for the email link. It can read and claim approvals and
#                        start the executor. It has NO EC2 permissions at all.
#   executor             the only thing that can touch EC2, and only in "live" mode.
#
# cleanup_mode is the one switch. In "dry_run" (the default) the executor is told to only
# look AND its IAM role has no permission to snapshot or delete, so a mistake in the code
# still cannot change anything. "live" turns on both.

data "aws_caller_identity" "current" {}

locals {
  live       = var.cleanup_mode == "live"
  account_id = data.aws_caller_identity.current.account_id
}

# --- Approvals table ---------------------------------------------------------------

# One item per approval link. Only the HASH of each link's secret is stored. Items expire
# on their own (DynamoDB TTL) a week after the link does.
resource "aws_dynamodb_table" "approvals" {
  # checkov:skip=CKV_AWS_28:Point-in-time recovery is skipped on purpose. Approvals are short-lived (24h links); losing them only means asking for new links.
  # checkov:skip=CKV_AWS_119:Encrypted at rest with the default AWS-owned key. The table holds hashes and ids, no secrets; a customer-managed KMS key adds cost and complexity.
  name         = "${local.name}-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approval_id"

  attribute {
    name = "approval_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# --- Executor: the only function that can act ---------------------------------------

resource "aws_cloudwatch_log_group" "executor" {
  # checkov:skip=CKV_AWS_158:Default CloudWatch encryption is enough for these logs; a customer-managed key adds cost and complexity.
  # checkov:skip=CKV_AWS_338:Operational logs, not audit logs. The audit trail is the approvals table. 30 days keeps storage near zero.
  name              = "/aws/lambda/${local.name}-cleanup-executor"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "executor" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.executor.arn}:*"]
  }

  # Read-only. Describe* calls do not support resource-level permissions.
  statement {
    sid       = "ReadVolumesAndSnapshots"
    actions   = ["ec2:DescribeVolumes", "ec2:DescribeSnapshots"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadAndUpdateApprovals"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.approvals.arn]
  }

  statement {
    sid       = "EmailTheOutcome"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.reports.arn]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

# The write permissions. Attached ONLY when cleanup_mode = "live".
data "aws_iam_policy_document" "executor_write" {
  statement {
    sid     = "BackUpVolumes"
    actions = ["ec2:CreateSnapshot"]
    resources = [
      "arn:aws:ec2:${var.region}:${local.account_id}:volume/*",
      "arn:aws:ec2:${var.region}::snapshot/*",
    ]
  }

  # Needed so the backup can be tagged at creation (guardian:backup-of). Only for snapshots
  # being created, not for tagging anything else.
  statement {
    sid       = "TagTheBackupWhileCreatingIt"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:${var.region}::snapshot/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSnapshot"]
    }
  }

  statement {
    sid       = "DeleteVolumes"
    actions   = ["ec2:DeleteVolume"]
    resources = ["arn:aws:ec2:${var.region}:${local.account_id}:volume/*"]
  }

  # A second safety layer, independent of the code: a volume carrying the guardian:ignore
  # tag (any value) can be neither backed up nor deleted by this role. An explicit Deny
  # always wins over an Allow. (AWS also refuses to delete a volume that is attached.)
  statement {
    sid       = "NeverTouchProtectedVolumes"
    effect    = "Deny"
    actions   = ["ec2:CreateSnapshot", "ec2:DeleteVolume"]
    resources = ["arn:aws:ec2:${var.region}:${local.account_id}:volume/*"]

    condition {
      test     = "Null"
      variable = "ec2:ResourceTag/guardian:ignore"
      values   = ["false"] # "the tag exists"
    }
  }
}

resource "aws_iam_role" "executor" {
  name               = "${local.name}-cleanup-executor"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "executor" {
  name   = "executor-least-privilege"
  role   = aws_iam_role.executor.id
  policy = data.aws_iam_policy_document.executor.json
}

resource "aws_iam_role_policy" "executor_write" {
  count = local.live ? 1 : 0

  name   = "executor-write-live-mode-only"
  role   = aws_iam_role.executor.id
  policy = data.aws_iam_policy_document.executor_write.json
}

resource "aws_lambda_function" "executor" {
  # checkov:skip=CKV_AWS_117:Function needs no VPC access; it only calls public AWS APIs. A VPC would require a NAT gateway or endpoints, which cost money.
  # checkov:skip=CKV_AWS_116:No dead-letter queue: it is started asynchronously by the approver with retries OFF on purpose (a retried deletion is worse than a missed one). Failures are recorded on the approval and emailed.
  # checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low concurrency limits. Runs only when a person presses a button.
  # checkov:skip=CKV_AWS_173:Environment variables hold no secrets (table name, topic ARN, numbers and a mode flag).
  # checkov:skip=CKV_AWS_272:Code signing is out of scope for this project.
  function_name = "${local.name}-cleanup-executor"
  description   = "Carries out ONE approved clean-up (back up, then delete an unattached volume). Started only by the approver. Dry-run unless cleanup_mode is live."

  role             = aws_iam_role.executor.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "cleanup_executor.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  # Waiting for a backup snapshot can take minutes for a big volume.
  timeout     = 900
  memory_size = 128

  environment {
    variables = {
      APPROVALS_TABLE = aws_dynamodb_table.approvals.name
      SNS_TOPIC_ARN   = aws_sns_topic.reports.arn
      MIN_AGE_DAYS    = tostring(var.min_age_days)
      # Only the exact word "false" enables real actions (see cleanup_executor.py).
      DRY_RUN = local.live ? "false" : "true"
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.executor,
    aws_iam_role_policy.executor,
  ]
}

# Never retry a clean-up automatically: running a deletion twice is worse than not at all.
resource "aws_lambda_function_event_invoke_config" "executor" {
  function_name          = aws_lambda_function.executor.function_name
  maximum_retry_attempts = 0
}

# --- Approver: the public page behind the email link --------------------------------

resource "aws_cloudwatch_log_group" "approver" {
  # checkov:skip=CKV_AWS_158:Default CloudWatch encryption is enough for these logs; a customer-managed key adds cost and complexity.
  # checkov:skip=CKV_AWS_338:Operational logs, not audit logs. 30 days keeps storage near zero.
  name              = "/aws/lambda/${local.name}-approver"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "approver" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.approver.arn}:*"]
  }

  # It can look at and use up approvals, nothing else. No EC2 permissions at all.
  statement {
    sid       = "ReadAndClaimApprovals"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.approvals.arn]
  }

  statement {
    sid       = "StartTheExecutor"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.executor.arn]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "approver" {
  name               = "${local.name}-approver"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "approver" {
  name   = "approver-least-privilege"
  role   = aws_iam_role.approver.id
  policy = data.aws_iam_policy_document.approver.json
}

resource "aws_lambda_function" "approver" {
  # checkov:skip=CKV_AWS_117:Function needs no VPC access; it only calls public AWS APIs. A VPC would require a NAT gateway or endpoints, which cost money.
  # checkov:skip=CKV_AWS_116:No dead-letter queue: it answers a web request synchronously, so there is nothing to retry.
  # checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low concurrency limits. Traffic is a handful of clicks.
  # checkov:skip=CKV_AWS_173:Environment variables hold no secrets (table name, function name and a mode flag).
  # checkov:skip=CKV_AWS_272:Code signing is out of scope for this project.
  function_name = "${local.name}-approver"
  description   = "Public confirmation page for clean-up links. Can claim approvals and start the executor; has no EC2 permissions."

  role             = aws_iam_role.approver.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "approver.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      APPROVALS_TABLE   = aws_dynamodb_table.approvals.name
      EXECUTOR_FUNCTION = aws_lambda_function.executor.function_name
      CLEANUP_MODE      = var.cleanup_mode
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.approver,
    aws_iam_role_policy.approver,
  ]
}

# The page has to be reachable from a browser with no AWS sign-in, so the URL is public.
# The unguessable one-time token in the link is the credential: 256 random bits, stored
# only as a hash, expiring after 24 hours, and a GET never acts (only the button does).
resource "aws_lambda_function_url" "approver" {
  # checkov:skip=CKV_AWS_258:A person clicking an email link has no AWS credentials, so AWS_IAM auth cannot work. Access is controlled by the one-time, expiring, hashed token; GET only shows a page, and the approver has no EC2 permissions.
  function_name      = aws_lambda_function.approver.function_name
  authorization_type = "NONE"
}

# Since October 2025 a public function URL needs BOTH permissions or it answers 403.
resource "aws_lambda_permission" "approver_url" {
  # checkov:skip=CKV_AWS_301:Public on purpose: a browser opening an email link has no AWS credentials. Protected by the one-time hashed token; GET never acts; the approver has no EC2 permissions.
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.approver.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "approver_url_invoke" {
  # checkov:skip=CKV_AWS_301:Required companion of the public function URL permission, and limited to calls that arrive through that URL (invoked_via_function_url).
  statement_id             = "FunctionURLInvokeAllowPublicAccess"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.approver.function_name
  principal                = "*"
  invoked_via_function_url = true
}
