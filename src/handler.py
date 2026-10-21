"""Lambda entry point: run the scanners, track findings over time, email what changed.

Read-only with respect to your infrastructure: nothing here modifies or deletes any
AWS resource. The only thing it writes is its own findings history (DynamoDB) and
the notification (SNS).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3

from findings_store import FindingStore, ScanDiff, finding_key
from scanners import ebs_unattached, eip_unassociated, snapshots_old
from scanners.common import Finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_ITEMS_IN_REPORT = 50


def error_label(exc: Exception) -> str:
    """Short, safe description of a failure (no message text)."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code")
    return code or type(exc).__name__


def run_scanners(
    ec2: Any, region: str, min_age_days: int, snapshot_min_age_days: int = 90
) -> tuple[list[Finding], list[str], set[str]]:
    """Run every scanner. One failing scanner must not hide the others' results.

    Returns (findings, errors, names of the scanners that completed successfully).
    """
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
    succeeded: set[str] = set()
    for name, run in scanners.items():
        try:
            findings.extend(run())
            succeeded.add(name)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
            logger.exception("Scanner %s failed", name)
            errors.append(f"{name}: {error_label(exc)}")

    findings.sort(key=lambda f: f.estimated_monthly_cost_usd, reverse=True)
    return findings, errors, succeeded


def _finding_lines(title: str, findings: list[Finding]) -> list[str]:
    lines = [title]
    for f in findings[:MAX_ITEMS_IN_REPORT]:
        lines.append(
            f"- [{f.severity.upper()}] {f.check} {f.resource_id}: {f.summary}, "
            f"~${f.estimated_monthly_cost_usd}/month"
        )
    hidden = len(findings) - MAX_ITEMS_IN_REPORT
    if hidden > 0:
        lines.append(f"...and {hidden} more (see CloudWatch Logs).")
    return lines + [""]


def _cost(findings: list[Finding]) -> float:
    return round(sum(f.estimated_monthly_cost_usd for f in findings), 2)


def format_report(
    findings: list[Finding],
    region: str,
    errors: list[str] | None = None,
    *,
    diff: ScanDiff | None = None,
    digest: bool = False,
) -> tuple[str, str]:
    """Build (subject, body) for the notification.

    `findings` is everything currently open. Without a `diff` (no findings store),
    every finding is reported as if new. With a diff, only what changed is listed,
    unless `digest` is true, in which case the still-open findings are listed too.
    """
    errors = errors or []
    total = _cost(findings)

    if diff is None:
        subject = f"[Cloud Guardian] {len(findings)} finding(s), ~${total}/month ({region})"
        new, resolved, still_open = findings, [], []
    else:
        new, resolved = diff.new, diff.resolved
        new_keys = {finding_key(f) for f in new}
        still_open = [f for f in findings if finding_key(f) not in new_keys]
        subject = (
            f"[Cloud Guardian] {len(new)} new, {len(resolved)} resolved, "
            f"{len(findings)} open (~${total}/month)"
        )
    if errors:
        subject += f" + {len(errors)} scanner error(s)"

    lines = [
        f"Cloud Guardian scan of {region}.",
        f"Open findings: {len(findings)}, estimated waste ~${total}/month "
        "(approximate list prices).",
        "",
    ]
    if new:
        title = "Findings:" if diff is None else "New since the last report:"
        lines += _finding_lines(title, new)
    if resolved:
        lines.append("Resolved since the last scan:")
        lines += [f"- {r['check']} {r['resource_id']}: {r['summary']}" for r in resolved]
        lines.append("")
    if still_open:
        if digest:
            lines += _finding_lines("Still open (weekly digest):", still_open)
        else:
            lines += [
                f"Still open, already reported: {len(still_open)} finding(s), "
                f"~${_cost(still_open)}/month. The full list is in the weekly digest.",
                "",
            ]
    if errors:
        lines += ["Scanner errors (details are in CloudWatch Logs):"]
        lines += [f"- {e}" for e in errors] + [""]

    lines += [
        "Nothing in your infrastructure was changed. Scans are read-only.",
        "To exclude a resource, add the tag guardian:ignore=true.",
    ]
    return subject[:100], "\n".join(lines)


def lambda_handler(event: dict[str, Any] | None, context: Any) -> dict[str, Any]:
    region = os.environ.get("AWS_REGION", "ap-south-1")
    min_age_days = int(os.environ.get("MIN_AGE_DAYS", "3"))
    snapshot_min_age_days = int(os.environ.get("SNAPSHOT_MIN_AGE_DAYS", "90"))
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    table_name = os.environ.get("FINDINGS_TABLE")
    digest_weekday = int(os.environ.get("DIGEST_WEEKDAY", "0"))  # 0 = Monday, UTC

    now = datetime.now(UTC)
    digest = bool((event or {}).get("digest")) or now.weekday() == digest_weekday

    ec2 = boto3.client("ec2", region_name=region)
    findings, errors, succeeded = run_scanners(ec2, region, min_age_days, snapshot_min_age_days)

    for finding in findings:
        logger.info(json.dumps(finding.to_dict(), default=str))

    # Track history. If the store breaks, fall back to reporting everything rather
    # than going quiet: a broken history must never hide waste.
    store: FindingStore | None = None
    diff: ScanDiff | None = None
    if table_name:
        store = FindingStore(boto3.resource("dynamodb", region_name=region).Table(table_name))
        try:
            diff = store.record_scan(findings, succeeded, region, now)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Findings store failed; reporting every finding")
            errors.append(f"findings-store: {error_label(exc)}")

    new = findings if diff is None else diff.new
    resolved = [] if diff is None else diff.resolved

    should_notify = bool(new or resolved or errors or (digest and diff is not None and findings))
    notified = False
    if should_notify:
        if topic_arn:
            subject, body = format_report(findings, region, errors, diff=diff, digest=digest)
            boto3.client("sns", region_name=region).publish(
                TopicArn=topic_arn, Subject=subject, Message=body
            )
            notified = True
        else:
            logger.warning("SNS_TOPIC_ARN is not set; skipping notification.")

    # Only after the email really went out do we remember it as announced.
    if notified and store is not None and diff is not None:
        try:
            store.mark_notified(diff.new, now)
        except Exception:  # noqa: BLE001
            logger.exception("Could not record notifications; findings will be re-announced")

    return {
        "findings": len(findings),
        "estimated_monthly_waste_usd": _cost(findings),
        "notified": notified,
        "errors": errors,
        "new": len(new),
        "resolved": len(resolved),
    }
