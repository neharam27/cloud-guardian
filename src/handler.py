"""Lambda entry point: run the scanners, log findings, email a summary via SNS.

Read-only by design. Nothing in here modifies or deletes any AWS resource.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

from scanners import ebs_unattached
from scanners.ebs_unattached import Finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_ITEMS_IN_REPORT = 50


def format_report(findings: list[Finding], region: str) -> tuple[str, str]:
    """Build (subject, body) for the notification."""
    total = round(sum(f.estimated_monthly_cost_usd for f in findings), 2)
    subject = f"[Cloud Guardian] {len(findings)} finding(s), ~${total}/month ({region})"

    lines = [
        f"Cloud Guardian found {len(findings)} issue(s) in {region}.",
        f"Estimated monthly waste: ~${total} (storage list prices; approximate).",
        "",
    ]
    for f in findings[:MAX_ITEMS_IN_REPORT]:
        ev = f.evidence
        lines.append(
            f"- [{f.severity.upper()}] {f.resource_id}: {ev['size_gib']} GiB {ev['volume_type']}, "
            f"unattached volume, created {ev['age_days']} day(s) ago, "
            f"~${f.estimated_monthly_cost_usd}/month"
        )
    hidden = len(findings) - MAX_ITEMS_IN_REPORT
    if hidden > 0:
        lines.append(f"...and {hidden} more (see CloudWatch Logs).")

    lines += [
        "",
        "Nothing was changed. This scan is read-only.",
        "To exclude a resource, add the tag guardian:ignore=true.",
    ]
    return subject[:100], "\n".join(lines)


def lambda_handler(event: dict[str, Any] | None, context: Any) -> dict[str, Any]:
    region = os.environ.get("AWS_REGION", "ap-south-1")
    min_age_days = int(os.environ.get("MIN_AGE_DAYS", "3"))
    topic_arn = os.environ.get("SNS_TOPIC_ARN")

    ec2 = boto3.client("ec2", region_name=region)
    findings = ebs_unattached.scan(ec2, region=region, min_age_days=min_age_days)

    for finding in findings:
        logger.info(json.dumps(finding.to_dict(), default=str))

    total = round(sum(f.estimated_monthly_cost_usd for f in findings), 2)
    notified = False

    if findings and topic_arn:
        subject, body = format_report(findings, region)
        boto3.client("sns", region_name=region).publish(
            TopicArn=topic_arn, Subject=subject, Message=body
        )
        notified = True
    elif findings:
        logger.warning("SNS_TOPIC_ARN is not set; skipping notification.")

    return {
        "findings": len(findings),
        "estimated_monthly_waste_usd": total,
        "notified": notified,
    }
