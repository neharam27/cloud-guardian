# GitHub Actions deploys through OpenID Connect (OIDC), so no AWS access key is ever stored
# on GitHub. GitHub proves who is asking with a short-lived signed token, and AWS hands out
# temporary credentials only if the token matches the conditions below.
#
# This lives in the bootstrap stack ON PURPOSE. The pipeline deploys the main stack, never
# this one, so the pipeline cannot edit its own permissions. Apply this stack by hand:
#
#   cd terraform/bootstrap
#   terraform plan     (expect only additions)
#   terraform apply
#
# OFF BY DEFAULT (enable_github_oidc = false). Some organizations forbid IAM OIDC providers
# with a service control policy, and then the very first resource below fails with
# "explicit deny in a service control policy". That is exactly what happened on the author's
# account, so the OIDC deploy is built and tested but has never run against real AWS.
#
# Two roles:
#   plan   read-only. Used for pull requests and for the plan step on main.
#   apply  can change only cloud-guardian-* resources in one region. Can be assumed ONLY by a
#          job that runs in the GitHub Environment named in var.github_environment, which is
#          where the human approval happens.

variable "enable_github_oidc" {
  description = "Create the GitHub OIDC provider and the two deploy roles. Leave false unless your organization allows IAM OIDC providers (a service control policy can forbid them)."
  type        = bool
  default     = false
}

variable "github_repo" {
  description = "The only GitHub repository allowed to deploy, as owner/name."
  type        = string
  default     = "neharam27/cloud-guardian"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repo))
    error_message = "github_repo must look like owner/name."
  }
}

variable "github_environment" {
  description = "Name of the GitHub Environment whose jobs may use the apply role (set it to require approval)."
  type        = string
  default     = "production"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.github_environment))
    error_message = "github_environment may contain only letters, digits, dots, dashes and underscores."
  }
}

locals {
  app_name   = "cloud-guardian"
  account_id = data.aws_caller_identity.current.account_id
  oidc_host  = "token.actions.githubusercontent.com"
  oidc_count = var.enable_github_oidc ? 1 : 0
}

resource "aws_iam_openid_connect_provider" "github" {
  count = local.oidc_count

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  # No thumbprint_list: AWS verifies GitHub's certificate with its own trusted CA library.
}

# --- Plan role: read-only ------------------------------------------------------------------

data "aws_iam_policy_document" "plan_trust" {
  count = local.oidc_count

  statement {
    sid     = "GitHubPlanJobs"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Pull requests of this repository, and runs on main. Nothing else.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values = [
        "repo:${var.github_repo}:pull_request",
        "repo:${var.github_repo}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "plan" {
  count = local.oidc_count

  name                 = "github-deploy-${local.app_name}-plan"
  description          = "GitHub Actions: read-only terraform plan for ${var.github_repo}"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust[0].json
  max_session_duration = 3600
}

# AWS's own read-only policy: enough for terraform to refresh and compare, changes nothing.
resource "aws_iam_role_policy_attachment" "plan_read_only" {
  count = local.oidc_count

  role       = aws_iam_role.plan[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# --- Apply role: scoped writes, only after approval ----------------------------------------

data "aws_iam_policy_document" "apply_trust" {
  count = local.oidc_count

  statement {
    sid     = "GitHubApprovedDeployJobs"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The token only carries this subject when the job runs in the protected environment.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repo}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "apply" {
  count = local.oidc_count

  name                 = "github-deploy-${local.app_name}-apply"
  description          = "GitHub Actions: terraform apply for ${var.github_repo}, only from the ${var.github_environment} environment"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust[0].json
  max_session_duration = 3600
}

# Reading is needed to refresh state before applying; the writes below are the scoped part.
resource "aws_iam_role_policy_attachment" "apply_read_only" {
  count = local.oidc_count

  role       = aws_iam_role.apply[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "apply" {
  count = local.oidc_count

  # checkov:skip=CKV_AWS_111:Write access is limited by resource name prefix, not by "*". A deploy role must be able to write the resources it deploys.
  # checkov:skip=CKV_AWS_107:Same as above. No credential-exposure actions are granted.
  # checkov:skip=CKV_AWS_109:IAM write actions exist so Terraform can manage this project's own roles. They are limited to roles named cloud-guardian-*, the deploy roles are explicitly denied, and policies cannot be attached from outside that prefix.
  # checkov:skip=CKV_AWS_110:Privilege escalation is possible in principle through the project's own roles; see "Residual risk" in the README. The deploy roles themselves are explicitly denied.
  # checkov:skip=CKV_AWS_356:Resources are scoped by name prefix. "*" is not used for any write action.

  statement {
    sid       = "StateBucketList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "StateObjectsAndLockFile"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/${local.app_name}/*"]
  }

  statement {
    sid       = "Lambda"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:${var.region}:${local.account_id}:function:${local.app_name}-*"]
  }

  statement {
    sid     = "DynamoDb"
    actions = ["dynamodb:*"]
    resources = [
      "arn:aws:dynamodb:${var.region}:${local.account_id}:table/${local.app_name}-*",
      "arn:aws:dynamodb:${var.region}:${local.account_id}:table/${local.app_name}-*/index/*",
    ]
  }

  statement {
    sid       = "Sns"
    actions   = ["sns:*"]
    resources = ["arn:aws:sns:${var.region}:${local.account_id}:${local.app_name}-*"]
  }

  statement {
    sid       = "Scheduler"
    actions   = ["scheduler:*"]
    resources = ["arn:aws:scheduler:${var.region}:${local.account_id}:schedule/default/${local.app_name}-*"]
  }

  statement {
    sid       = "LogGroups"
    actions   = ["logs:*"]
    resources = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.app_name}-*"]
  }

  # The project's own roles, by name prefix. No AttachRolePolicy: the stack only uses inline
  # policies, so the deploy role cannot attach AdministratorAccess or any managed policy.
  statement {
    sid = "ProjectRoles"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:ListRoleTags",
      "iam:PutRolePolicy",
      "iam:GetRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.app_name}-*"]
  }

  statement {
    sid       = "PassProjectRolesToLambdaAndScheduler"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.app_name}-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com", "scheduler.amazonaws.com"]
    }
  }

  # Belt and braces: even if a naming slip ever made these match a pattern above, an explicit
  # Deny always wins. The pipeline can never touch the roles that grant it access.
  statement {
    sid     = "NeverTouchTheDeployRolesOrTheirProvider"
    effect  = "Deny"
    actions = ["iam:*"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/github-deploy-*",
      aws_iam_openid_connect_provider.github[0].arn,
    ]
  }
}

resource "aws_iam_role_policy" "apply" {
  count = local.oidc_count

  name   = "scoped-writes"
  role   = aws_iam_role.apply[0].id
  policy = data.aws_iam_policy_document.apply[0].json
}

output "plan_role_arn" {
  description = "Store as the GitHub secret AWS_PLAN_ROLE_ARN"
  value       = one(aws_iam_role.plan[*].arn)
}

output "apply_role_arn" {
  description = "Store as the GitHub secret AWS_APPLY_ROLE_ARN"
  value       = one(aws_iam_role.apply[*].arn)
}
