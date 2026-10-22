"""Lambda: carry out ONE approved clean-up.

Started only by the approver Lambda, after a person pressed the confirm button. Never
started by the schedule or by a person directly.

Things this entry point is deliberately strict about:

  * The message carries only an approval id. Everything else (what to act on, whether
    the approval was really given) is re-read from the approvals table.
  * Whether this is a dry run is decided HERE, from this function's own configuration.
    Nothing in the message can switch it to a real run. Only the exact word "false" in
    DRY_RUN enables real actions; anything else (unset, empty, "0", a typo) is a dry run.
  * The outcome of a real run is emailed, success or not, so nothing happens silently.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3

from remediation import ebs_delete, executor
from remediation.approvals import ApprovalStore

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def is_dry_run(raw: str | None) -> bool:
    return (raw or "").strip().lower() != "false"


def _outcome_email(result: ebs_delete.Result, item: dict[str, Any] | None) -> tuple[str, str]:
    resource = (item or {}).get("finding_id", "unknown").split("#")[-1]
    subject = f"[Cloud Guardian] Clean-up {result.status}: {resource}"
    lines = [
        f"Clean-up result: {result.status}",
        f"Resource: {resource}",
        f"Details: {result.detail}",
    ]
    if result.snapshot_id:
        lines.append(f"Backup snapshot: {result.snapshot_id}")
    lines += [
        "",
        "This was started by an approval link you used. Nothing else was changed.",
        "A backup snapshot is kept; delete it when you no longer need it.",
    ]
    return subject[:100], "\n".join(lines)


def lambda_handler(event: dict[str, Any] | None, context: Any) -> dict[str, Any]:
    region = os.environ.get("AWS_REGION", "ap-south-1")
    dry_run = is_dry_run(os.environ.get("DRY_RUN"))
    min_age_days = int(os.environ.get("MIN_AGE_DAYS", "3"))
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    table_name = os.environ["APPROVALS_TABLE"]

    approval_id = event.get("approval_id") if isinstance(event, dict) else None
    if not isinstance(approval_id, str):
        return {"status": ebs_delete.STATUS_REFUSED, "detail": "no approval id", "dry_run": dry_run}

    store = ApprovalStore(boto3.resource("dynamodb", region_name=region).Table(table_name))
    item = store.get(approval_id)

    result = executor.run_by_id(
        approval_id,
        ec2=boto3.client("ec2", region_name=region),
        store=store,
        region=region,
        dry_run=dry_run,
        min_age_days=min_age_days,
    )
    logger.info("clean-up %s: %s (dry_run=%s)", approval_id[:12], result.status, dry_run)

    if not dry_run and topic_arn:
        try:
            subject, body = _outcome_email(result, item)
            boto3.client("sns", region_name=region).publish(
                TopicArn=topic_arn, Subject=subject, Message=body
            )
        except Exception:  # noqa: BLE001 - the action is done; never fail because of the email
            logger.exception("Could not send the clean-up outcome email")

    return {"status": result.status, "detail": result.detail, "dry_run": dry_run}
