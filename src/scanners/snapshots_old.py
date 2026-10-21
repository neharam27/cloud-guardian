"""Scanner: old EBS snapshots that nothing appears to need.

Read-only (ec2:DescribeSnapshots, ec2:DescribeImages, ec2:DescribeVolumes).

A snapshot is reported when ALL of these hold:
  * you own it (OwnerIds=self, so public/shared snapshots are never touched)
  * it is completed and at least `min_age_days` old
  * no AMI you own references it (AWS refuses to delete those anyway)
  * it is not managed by a lifecycle service (Data Lifecycle Manager or AWS Backup)
  * it does not carry the guardian:ignore tag

Evidence includes whether the source volume still exists. A snapshot whose
volume is gone is a stronger cleanup candidate than one whose volume is alive.

Limitations worth knowing:
  * Cost is an upper-bound style estimate: snapshots are incremental, so the real
    billed size is usually smaller than the volume size.
  * Deleting one snapshot in a chain may free little space, because later
    snapshots can depend on its blocks.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .common import Finding, is_ignored, severity_for, tags_to_dict
from .pricing import estimate_snapshot_monthly_cost

CHECK_NAME = "ebs-old-snapshot"

# AWS reports this volume ID for snapshots whose source volume is unknown
# (for example copies, or snapshots created by AMI import).
UNKNOWN_SOURCE_VOLUME = "vol-ffffffff"


def is_service_managed(tags: dict[str, str]) -> bool:
    """True for snapshots owned by a lifecycle service; those should not be hand-deleted."""
    return "dlm:managed" in tags or any(key.startswith("aws:backup") for key in tags)


def snapshot_ids_used_by_amis(ec2_client: Any) -> set[str]:
    """Snapshot IDs referenced by AMIs this account owns."""
    ids: set[str] = set()
    for image in ec2_client.describe_images(Owners=["self"])["Images"]:
        for mapping in image.get("BlockDeviceMappings", []):
            snapshot_id = mapping.get("Ebs", {}).get("SnapshotId")
            if snapshot_id:
                ids.add(snapshot_id)
    return ids


def existing_volume_ids(ec2_client: Any) -> set[str]:
    ids: set[str] = set()
    for page in ec2_client.get_paginator("describe_volumes").paginate():
        ids.update(volume["VolumeId"] for volume in page["Volumes"])
    return ids


def scan(
    ec2_client: Any,
    region: str,
    now: datetime | None = None,
    min_age_days: int = 90,
) -> list[Finding]:
    """Return one Finding per old, unused, non-ignored snapshot."""
    now = now or datetime.now(UTC)
    findings: list[Finding] = []

    used_by_amis = snapshot_ids_used_by_amis(ec2_client)
    volumes = existing_volume_ids(ec2_client)

    pages = ec2_client.get_paginator("describe_snapshots").paginate(OwnerIds=["self"])
    for page in pages:
        for snapshot in page["Snapshots"]:
            snapshot_id = snapshot["SnapshotId"]

            if snapshot.get("State") != "completed":
                continue
            if snapshot_id in used_by_amis:
                continue

            tags = tags_to_dict(snapshot.get("Tags"))
            if is_ignored(tags) or is_service_managed(tags):
                continue

            started_at = snapshot["StartTime"]
            age_days = (now - started_at).days
            if age_days < min_age_days:
                continue

            size_gib = snapshot.get("VolumeSize", 0)
            source_volume = snapshot.get("VolumeId")
            if not source_volume or source_volume == UNKNOWN_SOURCE_VOLUME:
                source_exists: bool | None = None
            else:
                source_exists = source_volume in volumes

            cost = estimate_snapshot_monthly_cost(size_gib)
            source_note = {
                True: "source volume still exists",
                False: "source volume deleted",
                None: "source volume unknown",
            }[source_exists]

            findings.append(
                Finding(
                    check=CHECK_NAME,
                    resource_id=snapshot_id,
                    resource_type="AWS::EC2::Snapshot",
                    region=region,
                    estimated_monthly_cost_usd=cost,
                    severity=severity_for(cost),
                    recommendation=(
                        "Delete the snapshot if you no longer need this restore point. "
                        "Add the tag guardian:ignore=true to keep it."
                    ),
                    summary=f"{size_gib} GiB snapshot, {age_days} day(s) old, {source_note}",
                    evidence={
                        "volume_size_gib": size_gib,
                        "source_volume_id": source_volume,
                        "source_volume_exists": source_exists,
                        "started_at": started_at.isoformat(),
                        "age_days": age_days,
                        "description": snapshot.get("Description") or None,
                        "encrypted": snapshot.get("Encrypted", False),
                        "tags": tags,
                        "cost_basis": (
                            "full volume size at standard-tier list price; "
                            "real cost is usually lower (snapshots are incremental)"
                        ),
                    },
                )
            )

    findings.sort(key=lambda f: f.estimated_monthly_cost_usd, reverse=True)
    return findings
