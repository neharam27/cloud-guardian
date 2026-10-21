"""Findings history in DynamoDB.

One item per finding, keyed by "<check>#<region>#<resource_id>":

    status        open | resolved          (indexed, see the by-status GSI)
    first_seen    when the finding first appeared
    last_seen     the most recent scan that still saw it
    resolved_at   when it stopped appearing
    notified_at   set ONLY after the email that mentioned it was sent

Why notified_at matters: a finding is recorded before the email is sent. If the
send fails, notified_at stays unset, so the next run still treats the finding as
new and mentions it. Nothing is silently lost.

Why `succeeded_checks` matters: a scanner that crashed tells us nothing about its
resources. Its open findings are left open, never marked resolved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Key

from scanners.common import Finding

STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"
STATUS_INDEX = "by-status"


def finding_key(finding: Finding) -> str:
    return f"{finding.check}#{finding.region}#{finding.resource_id}"


@dataclass
class ScanDiff:
    # Open findings that have not been announced yet (brand new, reopened, or
    # whose earlier announcement failed to send).
    new: list[Finding] = field(default_factory=list)
    # Open findings that were already announced.
    still_open: list[Finding] = field(default_factory=list)
    # Findings that were open last time and are gone now.
    resolved: list[dict[str, Any]] = field(default_factory=list)


class FindingStore:
    def __init__(self, table: Any) -> None:
        self.table = table

    def record_scan(
        self,
        findings: list[Finding],
        succeeded_checks: set[str],
        region: str,
        now: datetime | None = None,
    ) -> ScanDiff:
        stamp = (now or datetime.now(UTC)).isoformat()
        diff = ScanDiff()
        current: set[str] = set()

        for finding in findings:
            key = finding_key(finding)
            current.add(key)
            existing = self.table.get_item(Key={"finding_id": key}, ConsistentRead=True).get("Item")

            if existing and existing["status"] == STATUS_OPEN:
                self._refresh(key, finding, stamp)
                if existing.get("notified_at"):
                    diff.still_open.append(finding)
                else:
                    diff.new.append(finding)
            else:
                # Never seen before, or it was resolved and has come back.
                self.table.put_item(Item=self._new_item(key, finding, stamp))
                diff.new.append(finding)

        diff.resolved = self._resolve_missing(current, succeeded_checks, region, stamp)
        return diff

    def mark_notified(self, findings: list[Finding], now: datetime | None = None) -> None:
        stamp = (now or datetime.now(UTC)).isoformat()
        for finding in findings:
            self.table.update_item(
                Key={"finding_id": finding_key(finding)},
                UpdateExpression="SET notified_at = :t",
                ExpressionAttributeValues={":t": stamp},
            )

    # --- internals ---------------------------------------------------------

    @staticmethod
    def _new_item(key: str, finding: Finding, stamp: str) -> dict[str, Any]:
        return {
            "finding_id": key,
            "status": STATUS_OPEN,
            "check": finding.check,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "region": finding.region,
            "severity": finding.severity,
            "summary": finding.summary,
            "recommendation": finding.recommendation,
            # DynamoDB rejects Python floats, so numbers go in as Decimal.
            "estimated_monthly_cost_usd": Decimal(str(finding.estimated_monthly_cost_usd)),
            "evidence": json.dumps(finding.evidence, default=str),
            "first_seen": stamp,
            "last_seen": stamp,
        }

    def _refresh(self, key: str, finding: Finding, stamp: str) -> None:
        self.table.update_item(
            Key={"finding_id": key},
            UpdateExpression=(
                "SET last_seen = :t, severity = :sev, summary = :sum, "
                "estimated_monthly_cost_usd = :cost, evidence = :ev"
            ),
            ExpressionAttributeValues={
                ":t": stamp,
                ":sev": finding.severity,
                ":sum": finding.summary,
                ":cost": Decimal(str(finding.estimated_monthly_cost_usd)),
                ":ev": json.dumps(finding.evidence, default=str),
            },
        )

    def _open_items(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "IndexName": STATUS_INDEX,
            "KeyConditionExpression": Key("status").eq(STATUS_OPEN),
        }
        while True:
            response = self.table.query(**kwargs)
            items.extend(response["Items"])
            if "LastEvaluatedKey" not in response:
                return items
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    def _resolve_missing(
        self, current: set[str], succeeded_checks: set[str], region: str, stamp: str
    ) -> list[dict[str, Any]]:
        resolved: list[dict[str, Any]] = []
        for item in self._open_items():
            if item["finding_id"] in current:
                continue
            # Only judge what this scan could actually see.
            if item["region"] != region or item["check"] not in succeeded_checks:
                continue
            self.table.update_item(
                Key={"finding_id": item["finding_id"]},
                UpdateExpression="SET #s = :resolved, resolved_at = :t",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":resolved": STATUS_RESOLVED, ":t": stamp},
            )
            resolved.append(
                {
                    "finding_id": item["finding_id"],
                    "check": item["check"],
                    "resource_id": item["resource_id"],
                    "summary": item.get("summary", ""),
                    "first_seen": item.get("first_seen"),
                }
            )
        return resolved
