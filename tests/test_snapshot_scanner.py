from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

import handler
from scanners import snapshots_old
from scanners.pricing import estimate_snapshot_monthly_cost

REGION = "ap-south-1"
AZ = "ap-south-1a"
LONG_AGO = timedelta(days=200)


@pytest.fixture
def ec2(monkeypatch):
    """Overrides the shared fixture. moto normally pre-loads ~20 fake 'Auto-created snapshot
    for AMI' snapshots into every fake account; real AWS returns only your own snapshots, so
    switch the fakes off to start from an empty account."""
    monkeypatch.setenv("MOTO_EC2_LOAD_DEFAULT_AMIS", "false")
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


def make_volume(ec2, size=10):
    return ec2.create_volume(AvailabilityZone=AZ, Size=size, VolumeType="gp3")["VolumeId"]


def make_snapshot(ec2, volume_id, tags=None):
    kwargs = {"VolumeId": volume_id}
    if tags:
        kwargs["TagSpecifications"] = [
            {
                "ResourceType": "snapshot",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
    return ec2.create_snapshot(**kwargs)["SnapshotId"]


def later():
    return datetime.now(UTC) + LONG_AGO


# --- pricing -----------------------------------------------------------------


def test_snapshot_cost_scales_with_size():
    assert estimate_snapshot_monthly_cost(100) == 5.0
    assert estimate_snapshot_monthly_cost(0) == 0.0


# --- scanner -----------------------------------------------------------------


def test_old_snapshot_is_flagged_with_cost_and_evidence(ec2):
    volume_id = make_volume(ec2, size=100)
    snapshot_id = make_snapshot(ec2, volume_id)

    findings = snapshots_old.scan(ec2, REGION, now=later(), min_age_days=90)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == snapshot_id
    assert f.check == snapshots_old.CHECK_NAME
    assert f.estimated_monthly_cost_usd == estimate_snapshot_monthly_cost(100)
    assert f.evidence["age_days"] >= 199
    assert f.evidence["source_volume_id"] == volume_id
    assert f.evidence["source_volume_exists"] is True


def test_recent_snapshot_is_skipped(ec2):
    make_snapshot(ec2, make_volume(ec2))

    assert snapshots_old.scan(ec2, REGION, min_age_days=90) == []


def test_min_age_zero_flags_immediately(ec2):
    make_snapshot(ec2, make_volume(ec2))

    assert len(snapshots_old.scan(ec2, REGION, min_age_days=0)) == 1


def test_orphaned_snapshot_is_marked_as_such(ec2):
    volume_id = make_volume(ec2)
    make_snapshot(ec2, volume_id)
    ec2.delete_volume(VolumeId=volume_id)

    findings = snapshots_old.scan(ec2, REGION, min_age_days=0)

    assert len(findings) == 1
    assert findings[0].evidence["source_volume_exists"] is False
    assert "source volume deleted" in findings[0].summary


def test_snapshot_used_by_an_ami_is_not_flagged(ec2):
    unrelated = make_snapshot(ec2, make_volume(ec2))
    image_id = ec2.register_image(
        Name="guardian-test-ami",
        RootDeviceName="/dev/sda1",
        BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": "ignored"}}],
    )["ImageId"]
    # moto creates its own backing snapshot for the image, so ask for the real one.
    image = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    ami_snapshot = image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"]

    # Sanity check: without the exclusion this snapshot WOULD be a candidate.
    owned = {s["SnapshotId"] for s in ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]}
    assert ami_snapshot in owned

    flagged = [f.resource_id for f in snapshots_old.scan(ec2, REGION, min_age_days=0)]

    assert ami_snapshot not in flagged
    assert unrelated in flagged


def test_guardian_ignore_tag_is_respected(ec2):
    make_snapshot(ec2, make_volume(ec2), tags={"guardian:ignore": "true"})

    assert snapshots_old.scan(ec2, REGION, min_age_days=0) == []


def test_lifecycle_managed_snapshots_are_skipped(ec2):
    volume_id = make_volume(ec2)
    make_snapshot(ec2, volume_id, tags={"dlm:managed": "true"})
    make_snapshot(ec2, volume_id, tags={"aws:backup:source-resource": "x"})

    assert snapshots_old.scan(ec2, REGION, min_age_days=0) == []


def test_largest_snapshot_is_listed_first(ec2):
    small = make_snapshot(ec2, make_volume(ec2, size=5))
    big = make_snapshot(ec2, make_volume(ec2, size=500))

    findings = snapshots_old.scan(ec2, REGION, min_age_days=0)

    assert [f.resource_id for f in findings] == [big, small]


def test_no_snapshots_means_no_findings(ec2):
    assert snapshots_old.scan(ec2, REGION, min_age_days=0) == []


# --- handler -----------------------------------------------------------------


def test_handler_includes_snapshots_and_honours_the_env_setting(ec2, monkeypatch):
    make_snapshot(ec2, make_volume(ec2))

    # Default threshold is 90 days, so a brand-new snapshot is not reported.
    assert handler.lambda_handler({}, None)["findings"] == 0

    monkeypatch.setenv("SNAPSHOT_MIN_AGE_DAYS", "0")
    result = handler.lambda_handler({}, None)

    assert result["findings"] == 1
    assert result["errors"] == []
