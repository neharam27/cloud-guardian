"""Scanner: EBS volumes that are not attached to any instance.

This scanner is strictly read-only (it only calls ec2:DescribeVolumes).

Limitation worth knowing: DescribeVolumes does not say WHEN a volume was
detached, only when it was created. `min_age_days` therefore filters on volume
age, which is a proxy. A precise "unattached for N days" needs CloudTrail
(DetachVolume events) and is a later improvement.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .common import Finding, is_ignored, severity_for, tags_to_dict
from .pricing import estimate_ebs_monthly_cost

CHECK_NAME = "ebs-unattached-volume"


def evaluate_volume(
    volume: dict[str, Any], region: str, now: datetime, min_age_days: int
) -> Finding | None:
    """The single rule for "is this volume wasted?". Returns a Finding, or None.

    Used by the scanner AND by the approval-gated clean-up (which re-checks a volume
    with this exact function just before touching it), so the two can never disagree
    about what counts as wasted.
    """
    # Only a volume that is "available" (attached to nothing) can be wasted.
    if volume.get("State") != "available" or volume.get("Attachments"):
        return None

    tags = tags_to_dict(volume.get("Tags"))
    if is_ignored(tags):
        return None

    created_at = volume["CreateTime"]
    age_days = (now - created_at).days
    if age_days < min_age_days:
        return None

    size_gib = volume["Size"]
    volume_type = volume.get("VolumeType", "unknown")
    cost = estimate_ebs_monthly_cost(volume_type, size_gib, region)

    return Finding(
        check=CHECK_NAME,
        resource_id=volume["VolumeId"],
        resource_type="AWS::EC2::Volume",
        region=region,
        estimated_monthly_cost_usd=cost,
        severity=severity_for(cost),
        recommendation=(
            "Snapshot the volume if the data might be needed, then delete it. "
            "Add the tag guardian:ignore=true to keep it."
        ),
        summary=(
            f"{size_gib} GiB {volume_type} volume, unattached, created {age_days} day(s) ago"
        ),
        evidence={
            "state": volume["State"],
            "size_gib": size_gib,
            "volume_type": volume_type,
            "availability_zone": volume.get("AvailabilityZone"),
            "encrypted": volume.get("Encrypted", False),
            "created_at": created_at.isoformat(),
            "age_days": age_days,
            "source_snapshot_id": volume.get("SnapshotId") or None,
            "tags": tags,
            "cost_basis": "storage only; approximate list price (see pricing.py)",
        },
    )


def scan(
    ec2_client: Any,
    region: str,
    now: datetime | None = None,
    min_age_days: int = 3,
) -> list[Finding]:
    """Return one Finding per unattached, non-ignored volume older than min_age_days."""
    now = now or datetime.now(UTC)
    findings: list[Finding] = []

    paginator = ec2_client.get_paginator("describe_volumes")
    pages = paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}])

    for page in pages:
        for volume in page["Volumes"]:
            finding = evaluate_volume(volume, region, now, min_age_days)
            if finding is not None:
                findings.append(finding)

    findings.sort(key=lambda f: f.estimated_monthly_cost_usd, reverse=True)
    return findings
