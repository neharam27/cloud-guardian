"""Clean-up action: back up an unattached EBS volume, then delete it.

This is the only module in the project that can delete anything, and it is built so
that every doubt ends in "do nothing":

  1. The target must be exactly one EBS volume in this region (parsed strictly).
  2. The volume is looked at again, right now, with the SAME rule the scanner uses
     (scanners.ebs_unattached.evaluate_volume). Attached since? Tagged guardian:ignore
     since? Too young? Then refuse. Already gone? Then there is nothing to do.
  3. A snapshot is taken first. If it fails or never completes, nothing is deleted.
  4. Just before deleting, the snapshot must be completed AND be a snapshot of this
     very volume, and the volume is checked once more.
  5. Dry run is the default and makes no changes at all.

Only the validated volume id is ever passed to delete_volume.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from scanners import ebs_unattached
from scanners.common import is_ignored, tags_to_dict

ACTION = "delete-unattached-volume"

# Old-style (8 hex) and current (17 hex) volume ids. Nothing else is accepted.
_VOLUME_ID = re.compile(r"^vol-(?:[0-9a-f]{8}|[0-9a-f]{17})$")

STATUS_DRY_RUN = "dry_run"
STATUS_DONE = "done"
STATUS_REFUSED = "refused"
STATUS_ALREADY_GONE = "already_gone"
STATUS_FAILED = "failed"


@dataclass(frozen=True)
class Result:
    status: str
    detail: str
    snapshot_id: str | None = None


@dataclass(frozen=True)
class Target:
    volume_id: str
    region: str


class OutOfScope(Exception):
    """The finding is not something this action is allowed to act on."""


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "ClientError")


def parse_finding_id(finding_id: str, region: str) -> Target:
    """Accept only "ebs-unattached-volume#<this region>#<a well-formed volume id>"."""
    parts = finding_id.split("#") if isinstance(finding_id, str) else []
    if len(parts) != 3:
        raise OutOfScope("not a finding id this action understands")
    check, finding_region, resource_id = parts
    if check != ebs_unattached.CHECK_NAME:
        raise OutOfScope("this action only handles unattached EBS volumes")
    if finding_region != region:
        raise OutOfScope("the finding is in a different region")
    if not _VOLUME_ID.match(resource_id):
        raise OutOfScope("the resource is not a valid EBS volume id")
    return Target(volume_id=resource_id, region=region)


# --- the individual steps (kept separate so a state machine can call them) ------


def check_volume(
    ec2: Any, target: Target, now: datetime, min_age_days: int
) -> tuple[str, str]:
    """Look at the volume right now. Returns (verdict, why).

    verdict is "ok", "gone" or "refused".
    """
    if ec2.meta.region_name != target.region:
        return "refused", "the EC2 client is not in the finding's region"
    try:
        volumes = ec2.describe_volumes(VolumeIds=[target.volume_id])["Volumes"]
    except ClientError as exc:
        if _code(exc) == "InvalidVolume.NotFound":
            return "gone", "the volume no longer exists"
        raise
    if not volumes:
        return "gone", "the volume no longer exists"
    volume = volumes[0]

    if ebs_unattached.evaluate_volume(volume, target.region, now, min_age_days) is not None:
        return "ok", "the volume is still unattached and eligible"

    # Refused. Say why, in the order a person would care about.
    if volume.get("State") != "available" or volume.get("Attachments"):
        return "refused", "the volume is attached or in use now"
    if is_ignored(tags_to_dict(volume.get("Tags"))):
        return "refused", "the volume is tagged guardian:ignore"
    return "refused", "the volume no longer matches the scanner's rules (too new?)"


def start_snapshot(ec2: Any, target: Target, approval_ref: str = "") -> str:
    """Take a fresh backup snapshot of the volume and return its id."""
    tags = [
        {"Key": "guardian:backup-of", "Value": target.volume_id},
        {"Key": "guardian:reason", "Value": "backup before approved deletion"},
    ]
    if approval_ref:
        tags.append({"Key": "guardian:approval", "Value": approval_ref[:16]})
    response = ec2.create_snapshot(
        VolumeId=target.volume_id,
        Description=f"Cloud Guardian backup before deleting {target.volume_id}",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": tags}],
    )
    return response["SnapshotId"]


def snapshot_state(ec2: Any, snapshot_id: str) -> str:
    """pending | completed | error"""
    snapshot = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    return snapshot["State"]


def wait_for_snapshot(
    ec2: Any,
    snapshot_id: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
    max_wait_seconds: int = 600,
    poll_seconds: int = 5,
) -> str:
    """Poll until the snapshot is no longer pending. Returns the final state."""
    waited = 0
    state = snapshot_state(ec2, snapshot_id)
    while state == "pending" and waited < max_wait_seconds:
        sleep(poll_seconds)
        waited += poll_seconds
        state = snapshot_state(ec2, snapshot_id)
    return state


def delete_after_backup(
    ec2: Any, target: Target, snapshot_id: str, now: datetime, min_age_days: int
) -> Result:
    """Delete the volume, but only if the backup is real and the volume is still wasted."""
    try:
        snapshot = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    except ClientError as exc:
        return Result(STATUS_REFUSED, f"backup snapshot not found ({_code(exc)})", snapshot_id)

    if snapshot["State"] != "completed":
        return Result(STATUS_REFUSED, "the backup snapshot is not completed", snapshot_id)
    if snapshot.get("VolumeId") != target.volume_id:
        return Result(STATUS_REFUSED, "the snapshot is not a backup of this volume", snapshot_id)

    verdict, why = check_volume(ec2, target, now, min_age_days)
    if verdict == "gone":
        return Result(STATUS_ALREADY_GONE, why, snapshot_id)
    if verdict != "ok":
        return Result(STATUS_REFUSED, why, snapshot_id)

    try:
        ec2.delete_volume(VolumeId=target.volume_id)
    except ClientError as exc:
        if _code(exc) == "InvalidVolume.NotFound":
            return Result(STATUS_ALREADY_GONE, "the volume no longer exists", snapshot_id)
        return Result(STATUS_FAILED, f"delete failed ({_code(exc)})", snapshot_id)
    return Result(STATUS_DONE, f"deleted {target.volume_id}; backup is {snapshot_id}", snapshot_id)


# --- the whole action ---------------------------------------------------------


def remediate(
    ec2: Any,
    finding_id: str,
    *,
    region: str,
    dry_run: bool = True,
    now: datetime | None = None,
    min_age_days: int = 3,
    approval_ref: str = "",
    sleep: Callable[[float], None] = time.sleep,
    max_wait_seconds: int = 600,
) -> Result:
    """Run the whole action for one finding. Never raises for an expected refusal."""
    now = now or datetime.now(UTC)

    try:
        target = parse_finding_id(finding_id, region)
    except OutOfScope as exc:
        return Result(STATUS_REFUSED, str(exc))

    verdict, why = check_volume(ec2, target, now, min_age_days)
    if verdict == "gone":
        return Result(STATUS_ALREADY_GONE, why)
    if verdict != "ok":
        return Result(STATUS_REFUSED, why)

    if dry_run:
        return Result(
            STATUS_DRY_RUN,
            f"would snapshot {target.volume_id}, then delete it (dry run: nothing was changed)",
        )

    try:
        snapshot_id = start_snapshot(ec2, target, approval_ref)
    except ClientError as exc:
        return Result(STATUS_FAILED, f"could not create the backup ({_code(exc)}); nothing deleted")

    try:
        state = wait_for_snapshot(ec2, snapshot_id, sleep=sleep, max_wait_seconds=max_wait_seconds)
    except ClientError as exc:
        return Result(
            STATUS_FAILED,
            f"could not check the backup ({_code(exc)}); volume kept",
            snapshot_id,
        )
    if state != "completed":
        return Result(
            STATUS_FAILED,
            f"the backup did not complete (state: {state}); volume kept",
            snapshot_id,
        )

    return delete_after_backup(ec2, target, snapshot_id, now, min_age_days)
