"""One-time approvals for clean-up actions.

How it works: when Cloud Guardian proposes an action, it creates a random token and
puts it in the approval link. Only the SHA-256 hash of the token is stored, so reading
the table (or its backups) never reveals a usable link.

An approval is valid when it is:
  * known       (the hash exists),
  * unexpired   (24 hours by default),
  * unused      (it can be claimed exactly once).

Claiming is a single conditional write, so two people clicking at the same moment
cannot both succeed. If the action then fails, the approval stays used: a human has to
ask for a fresh one. That is deliberate, because "never run twice" matters more than
"retry for me".
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

STATUS_PENDING = "pending"
STATUS_CLAIMED = "claimed"

DEFAULT_TTL_SECONDS = 24 * 60 * 60
# Keep spent approvals a while after expiry so a late click can be told "expired"
# rather than "unknown". DynamoDB's TTL feature removes them afterwards.
_RETENTION_SECONDS = 7 * 24 * 60 * 60
_MAX_TOKEN_LENGTH = 200


class ApprovalError(Exception):
    """The approval cannot be used. `reason` is safe to show to the person who clicked."""

    reason = "This approval link is not valid."


class UnknownApproval(ApprovalError):
    reason = "This approval link is not valid."


class ExpiredApproval(ApprovalError):
    reason = "This approval link has expired. Ask Cloud Guardian for a new one."


class UsedApproval(ApprovalError):
    reason = "This approval link was already used."


@dataclass(frozen=True)
class Approval:
    approval_id: str  # the hash; safe to log
    finding_id: str
    action: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _epoch(moment: datetime) -> int:
    return int(moment.timestamp())


class ApprovalStore:
    def __init__(self, table: Any) -> None:
        self.table = table

    def create(
        self,
        finding_id: str,
        action: str,
        now: datetime | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> str:
        """Record a pending approval and return the secret token for the link."""
        now = now or datetime.now(UTC)
        token = secrets.token_urlsafe(32)
        expires_at = _epoch(now) + ttl_seconds
        self.table.put_item(
            Item={
                "approval_id": hash_token(token),
                "finding_id": finding_id,
                "action": action,
                "status": STATUS_PENDING,
                "created_at": now.isoformat(),
                "expires_at": expires_at,
                # DynamoDB TTL attribute (epoch seconds).
                "ttl": expires_at + _RETENTION_SECONDS,
            }
        )
        return token

    def peek(self, token: str, now: datetime | None = None) -> Approval:
        """Check an approval WITHOUT using it up (for dry runs)."""
        now = now or datetime.now(UTC)
        item = self._get(token)
        if item is None:
            raise UnknownApproval
        if item["status"] != STATUS_PENDING:
            raise UsedApproval
        if int(item["expires_at"]) <= _epoch(now):
            raise ExpiredApproval
        return self._approval(item)

    def claim(self, token: str, now: datetime | None = None) -> Approval:
        """Use the approval up. Succeeds at most once, even under concurrent clicks."""
        now = now or datetime.now(UTC)
        if not token or len(token) > _MAX_TOKEN_LENGTH:
            raise UnknownApproval
        try:
            response = self.table.update_item(
                Key={"approval_id": hash_token(token)},
                UpdateExpression="SET #s = :claimed, claimed_at = :now",
                ConditionExpression=(
                    "attribute_exists(approval_id) AND #s = :pending AND expires_at > :epoch"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":claimed": STATUS_CLAIMED,
                    ":pending": STATUS_PENDING,
                    ":now": now.isoformat(),
                    ":epoch": _epoch(now),
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            # Work out why, only so the message to the person is accurate.
            self.peek(token, now)  # raises the specific reason
            raise UnknownApproval from exc  # pragma: no cover - lost a race we cannot name
        return self._approval(response["Attributes"])

    def finish(
        self, approval: Approval, outcome: str, detail: str, now: datetime | None = None
    ) -> None:
        """Record what happened, for the audit trail."""
        now = now or datetime.now(UTC)
        self.table.update_item(
            Key={"approval_id": approval.approval_id},
            UpdateExpression="SET outcome = :o, detail = :d, finished_at = :t",
            ExpressionAttributeValues={":o": outcome, ":d": detail, ":t": now.isoformat()},
        )

    # --- internals ---------------------------------------------------------

    def _get(self, token: str) -> dict[str, Any] | None:
        if not token or len(token) > _MAX_TOKEN_LENGTH:
            return None
        return self.table.get_item(
            Key={"approval_id": hash_token(token)}, ConsistentRead=True
        ).get("Item")

    @staticmethod
    def _approval(item: dict[str, Any]) -> Approval:
        return Approval(
            approval_id=item["approval_id"],
            finding_id=item["finding_id"],
            action=item["action"],
        )
