"""Shared building blocks for every scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

IGNORE_TAG = "guardian:ignore"


@dataclass(frozen=True)
class Finding:
    check: str
    resource_id: str
    resource_type: str
    region: str
    estimated_monthly_cost_usd: float
    severity: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # One human-readable line used in the email report.
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def tags_to_dict(raw_tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (raw_tags or [])}


def is_ignored(tags: dict[str, str]) -> bool:
    """A resource opts out by carrying the guardian:ignore tag.

    Any value ignores it, except an explicit "false".
    """
    if IGNORE_TAG not in tags:
        return False
    return tags[IGNORE_TAG].strip().lower() != "false"


def severity_for(monthly_cost_usd: float) -> str:
    if monthly_cost_usd >= 20:
        return "high"
    if monthly_cost_usd >= 5:
        return "medium"
    return "low"
