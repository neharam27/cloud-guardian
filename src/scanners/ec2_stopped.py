"""Scanner: EC2 instances that have been stopped for a long time.

A stopped instance costs nothing for compute, but its EBS volumes keep billing
every month. They are easy to forget, so this reports the instances and the
storage they are still paying for.

This scanner is strictly read-only (ec2:DescribeInstances and ec2:DescribeVolumes).

How "stopped for N days" is worked out: DescribeInstances has no stop-time field.
The only record is inside the free-text StateTransitionReason, for example
"User initiated (2026-10-21 16:43:01 GMT)". That text is parsed here. Some stops
carry no timestamp (for example a shutdown from inside the operating system). For
those the stop time is unknown, so the launch time is used only as an upper bound:
an instance launched less than `min_age_days` ago cannot have been stopped that
long and is skipped, and anything older is reported and clearly marked "stop time
unknown" rather than guessed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .common import Finding, is_ignored, severity_for, tags_to_dict
from .pricing import estimate_ebs_monthly_cost

CHECK_NAME = "ec2-long-stopped-instance"

# AWS writes "GMT", moto writes "UTC". Both mean UTC.
_STOP_TIME = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:GMT|UTC)\)")

# describe_volumes accepts at most 200 values per filter; stay well under it.
_VOLUME_BATCH = 100

_NAME_MAX_CHARS = 40


def parse_stop_time(transition_reason: str | None) -> datetime | None:
    """Return when the instance was stopped, or None if the reason has no timestamp."""
    match = _STOP_TIME.search(transition_reason or "")
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def _volume_details(ec2_client: Any, volume_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Look up size and type for the given volumes. Unknown volumes are simply absent."""
    details: dict[str, dict[str, Any]] = {}
    for start in range(0, len(volume_ids), _VOLUME_BATCH):
        batch = volume_ids[start : start + _VOLUME_BATCH]
        paginator = ec2_client.get_paginator("describe_volumes")
        # A filter (not VolumeIds) so that a volume deleted in the meantime does not
        # make the whole call fail.
        for page in paginator.paginate(Filters=[{"Name": "volume-id", "Values": batch}]):
            for volume in page["Volumes"]:
                details[volume["VolumeId"]] = volume
    return details


def _safe_name(tags: dict[str, str]) -> str:
    """The Name tag, made safe for a one-line email summary.

    AWS already restricts tag characters, so this is defensive: it drops control
    characters (including newlines) and caps the length. Non-English names are kept.
    """
    name = re.sub(r"[\x00-\x1f\x7f]", "", tags.get("Name", "")).strip()
    return name[:_NAME_MAX_CHARS]


def scan(
    ec2_client: Any,
    region: str,
    now: datetime | None = None,
    min_age_days: int = 14,
) -> list[Finding]:
    """Return one Finding per stopped, non-ignored instance stopped at least min_age_days."""
    now = now or datetime.now(UTC)

    candidates: list[dict[str, Any]] = []
    paginator = ec2_client.get_paginator("describe_instances")
    pages = paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}])
    for page in pages:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                # Defensive: the API filter should already guarantee this.
                if instance.get("State", {}).get("Name") != "stopped":
                    continue

                tags = tags_to_dict(instance.get("Tags"))
                if is_ignored(tags):
                    continue

                stopped_at = parse_stop_time(instance.get("StateTransitionReason"))
                if stopped_at is not None:
                    days_stopped: int | None = max(0, (now - stopped_at).days)
                    if days_stopped < min_age_days:
                        continue
                else:
                    days_stopped = None
                    launched_days = (now - instance["LaunchTime"]).days
                    if launched_days < min_age_days:
                        continue

                candidates.append(
                    {
                        "instance": instance,
                        "tags": tags,
                        "stopped_at": stopped_at,
                        "days_stopped": days_stopped,
                    }
                )

    volume_ids = [
        mapping["Ebs"]["VolumeId"]
        for c in candidates
        for mapping in c["instance"].get("BlockDeviceMappings", [])
        if "Ebs" in mapping
    ]
    volumes = _volume_details(ec2_client, volume_ids) if volume_ids else {}

    findings: list[Finding] = []
    for c in candidates:
        instance, tags = c["instance"], c["tags"]

        attached = [
            volumes[m["Ebs"]["VolumeId"]]
            for m in instance.get("BlockDeviceMappings", [])
            if "Ebs" in m and m["Ebs"]["VolumeId"] in volumes
        ]
        total_gib = sum(v["Size"] for v in attached)
        cost = round(
            sum(
                estimate_ebs_monthly_cost(v.get("VolumeType", "unknown"), v["Size"], region)
                for v in attached
            ),
            2,
        )

        instance_type = instance.get("InstanceType", "unknown")
        name = _safe_name(tags)
        label = f"{instance_type} instance" + (f' "{name}"' if name else "")
        if c["days_stopped"] is not None:
            when = f"stopped {c['days_stopped']} day(s)"
        else:
            launched_days = (now - instance["LaunchTime"]).days
            when = f"stopped (stop time unknown, launched {launched_days} day(s) ago)"

        findings.append(
            Finding(
                check=CHECK_NAME,
                resource_id=instance["InstanceId"],
                resource_type="AWS::EC2::Instance",
                region=region,
                estimated_monthly_cost_usd=cost,
                severity=severity_for(cost),
                recommendation=(
                    "If it is no longer needed, create an AMI or snapshot first if the data "
                    "might matter, then terminate the instance and delete its volumes. "
                    "Add the tag guardian:ignore=true to keep it."
                ),
                summary=f"{label} {when}, {total_gib} GiB of disks still billing",
                evidence={
                    "instance_type": instance_type,
                    "stop_time_known": c["stopped_at"] is not None,
                    "stopped_at": c["stopped_at"].isoformat() if c["stopped_at"] else None,
                    "days_stopped": c["days_stopped"],
                    "launch_time": instance["LaunchTime"].isoformat(),
                    "availability_zone": instance.get("Placement", {}).get("AvailabilityZone"),
                    "volume_ids": sorted(v["VolumeId"] for v in attached),
                    "volume_gib_total": total_gib,
                    "tags": tags,
                    "cost_basis": (
                        "attached EBS storage only; approximate list price (see pricing.py); "
                        "excludes snapshots and Elastic IPs"
                    ),
                },
            )
        )

    findings.sort(key=lambda f: f.estimated_monthly_cost_usd, reverse=True)
    return findings
