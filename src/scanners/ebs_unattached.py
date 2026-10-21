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
            # Defensive: the API filter should already guarantee this.
            if volume.get("Attachments"):
                continue

            tags = tags_to_dict(volume.get("Tags"))
            if is_ignored(tags):
                continue

            created_at = volume["CreateTime"]
            age_days = (now - created_at).days
            if age_days < min_age_days:
                continue

            size_gib = volume["Size"]
            volume_type = volume.get("VolumeType", "unknown")
            cost = estimate_ebs_monthly_cost(volume_type, size_gib, region)

            findings.append(
                Finding(
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
                        f"{size_gib} GiB {volume_type} volume, unattached, "
                        f"created {age_days} day(s) ago"
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
            )

    findings.sort(key=lambda f: f.estimated_monthly_cost_usd, reverse=True)
    return findings
