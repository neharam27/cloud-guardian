"""Lambda entry point: run the scanners, log findings, email a summary via SNS.

Read-only by design. Nothing in here modifies or deletes any AWS resource.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

from scanners import ebs_unattached, eip_unassociated, snapshots_old
from scanners.common import Finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_ITEMS_IN_REPORT = 50


def error_label(exc: Exception) -> str:
    """Short, safe description of a scanner failure (no message text)."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code")
    return code or type(exc).__name__


def run_scanners(
    ec2: Any, region: str, min_age_days: int, snapshot_min_age_days: int = 90
) -> tuple[list[Finding], list[str]]:
    """Run every scanner. One failing scanner must not hide the others' results."""
    scanners = {
        ebs_unattached.CHECK_NAME: lambda: ebs_unattached.scan(
            ec2, region=region, min_age_days=min_age_days
        ),
        eip_unassociated.CHECK_NAME: lambda: eip_unassociated.scan(ec2, region=region),
        snapshots_old.CHECK_NAME: lambda: snapshots_old.scan(
            ec2, region=region, min_age_days=snapshot_min_age_days
        ),
    }

    findings: list[Finding] = []
    errors: list[str] = []
    for name, run in scanners.items():
        try:
            findings.extend(run())
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
            logger.exception("Scanner %s failed", name)
            errors.append(f"{name}: {error_label(exc)}")

    findings.sort(key=lambda f: f.estimated_monthly_cost_usd, reverse=True)
    return findings, errors


def format_report(
    findings: list[Finding], region: str, errors: list[str] | None = None
) -> tuple[str, str]:
    """Build (subject, body) for the notification."""
    errors = errors or []
    total = round(sum(f.estimated_monthly_cost_usd for f in findings), 2)
    subject = f"[Cloud Guardian] {len(findings)} finding(s), ~${total}/month ({region})"
    if errors:
        subject += f" + {len(errors)} scanner error(s)"

    lines = [
        f"Cloud Guardian found {len(findings)} issue(s) in {region}.",
        f"Estimated monthly waste: ~${total} (approximate list prices).",
        "",
    ]
    for f in findings[:MAX_ITEMS_IN_REPORT]:
        lines.append(
            f"- [{f.severity.upper()}] {f.check} {f.resource_id}: {f.summary}, "
            f"~${f.estimated_monthly_cost_usd}/month"
        )
    hidden = len(findings) - MAX_ITEMS_IN_REPORT
    if hidden > 0:
        lines.append(f"...and {hidden} more (see CloudWatch Logs).")

    if errors:
        lines += ["", "Scanner errors (details are in CloudWatch Logs):"]
        lines += [f"- {e}" for e in errors]

    lines += [
        "",
        "Nothing was changed. This scan is read-only.",
        "To exclude a resource, add the tag guardian:ignore=true.",
    ]
    return subject[:100], "\n".join(lines)


def lambda_handler(event: dict[str, Any] | None, context: Any) -> dict[str, Any]:
    region = os.environ.get("AWS_REGION", "ap-south-1")
    min_age_days = int(os.environ.get("MIN_AGE_DAYS", "3"))
    snapshot_min_age_days = int(os.environ.get("SNAPSHOT_MIN_AGE_DAYS", "90"))
    topic_arn = os.environ.get("SNS_TOPIC_ARN")

    ec2 = boto3.client("ec2", region_name=region)
    findings, errors = run_scanners(ec2, region, min_age_days, snapshot_min_age_days)

    for finding in findings:
        logger.info(json.dumps(finding.to_dict(), default=str))

    total = round(sum(f.estimated_monthly_cost_usd for f in findings), 2)
    notified = False

    # Email when there is something to say: findings, or a scanner that broke.
    if findings or errors:
        if topic_arn:
            subject, body = format_report(findings, region, errors)
            boto3.client("sns", region_name=region).publish(
                TopicArn=topic_arn, Subject=subject, Message=body
            )
            notified = True
        else:
            logger.warning("SNS_TOPIC_ARN is not set; skipping notification.")

    return {
        "findings": len(findings),
        "estimated_monthly_waste_usd": total,
        "notified": notified,
        "errors": errors,
    }
