"""Glue: turn an approval into a (safe) action, and keep an audit record.

Two entry points:

  execute(token, ...)        one process does it all: claim the approval, act, record.
                             Dry run only PEEKS (the approval stays usable).

  run_by_id(approval_id, ...) for the executor Lambda, which is started by the approver
                             Lambda AFTER the approval was claimed. It trusts nothing in
                             the message except the id: it re-reads the approval from the
                             database, insists it was really claimed, and flips it to
                             "running" in one conditional write so a duplicate or retried
                             message cannot act twice.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from remediation import ebs_delete
from remediation.approvals import (
    STATUS_CLAIMED,
    STATUS_PENDING,
    Approval,
    ApprovalError,
    ApprovalStore,
)

# The only action this build knows. Anything else in an approval is refused.
KNOWN_ACTIONS = {ebs_delete.ACTION}


def _act(
    approval: Approval,
    *,
    ec2: Any,
    region: str,
    dry_run: bool,
    now: datetime,
    min_age_days: int,
    sleep: Callable[[float], None],
) -> ebs_delete.Result:
    if approval.action not in KNOWN_ACTIONS:
        return ebs_delete.Result(ebs_delete.STATUS_REFUSED, "unknown action")
    try:
        return ebs_delete.remediate(
            ec2,
            approval.finding_id,
            region=region,
            dry_run=dry_run,
            now=now,
            min_age_days=min_age_days,
            approval_ref=approval.approval_id,
            sleep=sleep,
        )
    except Exception as exc:  # noqa: BLE001 - the approval is already used; record why
        # Deleting is always the very last call, so an error here means nothing was
        # deleted. Say so, keep the exception type only (no message text).
        return ebs_delete.Result(
            ebs_delete.STATUS_FAILED,
            f"unexpected error ({type(exc).__name__}); nothing further was attempted",
        )


def execute(
    token: str,
    *,
    ec2: Any,
    store: ApprovalStore,
    region: str,
    dry_run: bool = True,
    now: datetime | None = None,
    min_age_days: int = 3,
    sleep: Callable[[float], None] = time.sleep,
) -> ebs_delete.Result:
    now = now or datetime.now(UTC)

    approval: Approval
    try:
        approval = store.peek(token, now) if dry_run else store.claim(token, now)
    except ApprovalError as exc:
        return ebs_delete.Result(ebs_delete.STATUS_REFUSED, exc.reason)

    result = _act(
        approval,
        ec2=ec2,
        region=region,
        dry_run=dry_run,
        now=now,
        min_age_days=min_age_days,
        sleep=sleep,
    )
    if not dry_run:
        store.finish(approval, result.status, result.detail, now)
    return result


def run_by_id(
    approval_id: str,
    *,
    ec2: Any,
    store: ApprovalStore,
    region: str,
    dry_run: bool = True,
    now: datetime | None = None,
    min_age_days: int = 3,
    sleep: Callable[[float], None] = time.sleep,
) -> ebs_delete.Result:
    """Run an approval that the approver already claimed (or, in a dry run, peeked)."""
    now = now or datetime.now(UTC)

    item = store.get(approval_id)
    if item is None:
        return ebs_delete.Result(ebs_delete.STATUS_REFUSED, "unknown approval")

    status = item.get("status")
    if dry_run:
        if status not in (STATUS_PENDING, STATUS_CLAIMED):
            return ebs_delete.Result(ebs_delete.STATUS_REFUSED, "approval is not usable")
    else:
        if status != STATUS_CLAIMED:
            return ebs_delete.Result(ebs_delete.STATUS_REFUSED, "approval was not approved")
        if not store.begin(approval_id, now):
            return ebs_delete.Result(
                ebs_delete.STATUS_REFUSED, "this approval already started or finished"
            )

    approval = Approval(
        approval_id=item["approval_id"],
        finding_id=item["finding_id"],
        action=item["action"],
    )
    result = _act(
        approval,
        ec2=ec2,
        region=region,
        dry_run=dry_run,
        now=now,
        min_age_days=min_age_days,
        sleep=sleep,
    )
    if not dry_run:
        store.finish(approval, result.status, result.detail, now)
    return result
