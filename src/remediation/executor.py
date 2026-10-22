"""Glue: turn an approval token into a (safe) action, and keep an audit record.

Order matters:
  real run:  claim the approval first (so it can never run twice), then act, then record.
  dry run:   only PEEK at the approval (it stays usable), act in dry-run mode, record nothing.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from remediation import ebs_delete
from remediation.approvals import Approval, ApprovalError, ApprovalStore

# The only action this build knows. Anything else in an approval is refused.
KNOWN_ACTIONS = {ebs_delete.ACTION}


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

    if approval.action not in KNOWN_ACTIONS:
        result = ebs_delete.Result(ebs_delete.STATUS_REFUSED, "unknown action")
    else:
        try:
            result = ebs_delete.remediate(
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
            result = ebs_delete.Result(
                ebs_delete.STATUS_FAILED,
                f"unexpected error ({type(exc).__name__}); nothing further was attempted",
            )

    if not dry_run:
        store.finish(approval, result.status, result.detail, now)
    return result
