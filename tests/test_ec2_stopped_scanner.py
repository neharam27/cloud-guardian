from datetime import UTC, datetime, timedelta

import pytest

from scanners import ec2_stopped
from scanners.ec2_stopped import parse_stop_time
from scanners.pricing import estimate_ebs_monthly_cost

REGION = "ap-south-1"


def root_volume(size=20, volume_type="gp3"):
    return {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": size, "VolumeType": volume_type}}


def make_instance(ec2, *, stopped=True, tags=None, volumes=None, instance_type="t3.micro"):
    """Launch a fake instance and (by default) stop it. Returns the instance id."""
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    kwargs = {
        "ImageId": image_id,
        "MinCount": 1,
        "MaxCount": 1,
        "InstanceType": instance_type,
        "BlockDeviceMappings": volumes or [root_volume()],
    }
    if tags:
        kwargs["TagSpecifications"] = [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
    instance_id = ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]
    if stopped:
        ec2.stop_instances(InstanceIds=[instance_id])
    return instance_id


def stop_time_of(ec2, instance_id):
    reason = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
        "StateTransitionReason"
    ]
    stopped_at = parse_stop_time(reason)
    assert stopped_at is not None, reason
    return stopped_at


def later(days):
    return datetime.now(UTC) + timedelta(days=days)


# --- parsing the stop time ---------------------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        "User initiated (2026-10-21 16:43:01 GMT)",  # what real AWS writes
        "User initiated (2026-10-21 16:43:01 UTC)",  # what moto writes
    ],
)
def test_parse_stop_time_reads_both_spellings(reason):
    assert parse_stop_time(reason) == datetime(2026, 10, 21, 16, 43, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "reason",
    [
        None,
        "",
        "Client.UserInitiatedShutdown: User initiated shutdown",
        "Server.SpotInstanceTermination: Spot instance terminated",
        "User initiated (not a date)",
    ],
)
def test_parse_stop_time_returns_none_without_a_timestamp(reason):
    assert parse_stop_time(reason) is None


# --- scanner -----------------------------------------------------------------


def test_finds_long_stopped_instance_with_cost_and_evidence(ec2):
    instance_id = make_instance(ec2, volumes=[root_volume(size=100, volume_type="gp3")])

    findings = ec2_stopped.scan(ec2, REGION, now=later(30), min_age_days=14)

    assert len(findings) == 1
    f = findings[0]
    assert f.check == ec2_stopped.CHECK_NAME
    assert f.resource_id == instance_id
    assert f.resource_type == "AWS::EC2::Instance"
    assert f.estimated_monthly_cost_usd == estimate_ebs_monthly_cost("gp3", 100, REGION)
    assert f.evidence["stop_time_known"] is True
    assert f.evidence["days_stopped"] >= 29
    assert f.evidence["volume_gib_total"] == 100
    assert f.evidence["instance_type"] == "t3.micro"
    assert len(f.evidence["volume_ids"]) == 1
    assert "100 GiB" in f.summary
    assert "stopped 3" in f.summary  # about 30 days
    assert f.severity in {"low", "medium", "high"}


def test_running_instance_is_not_flagged(ec2):
    make_instance(ec2, stopped=False)

    assert ec2_stopped.scan(ec2, REGION, now=later(365), min_age_days=0) == []


def test_recently_stopped_instance_is_skipped(ec2):
    make_instance(ec2)

    assert ec2_stopped.scan(ec2, REGION, min_age_days=14) == []


def test_min_age_zero_flags_a_just_stopped_instance(ec2):
    make_instance(ec2)

    assert len(ec2_stopped.scan(ec2, REGION, min_age_days=0)) == 1


def test_age_threshold_boundary(ec2):
    instance_id = make_instance(ec2)
    stopped_at = stop_time_of(ec2, instance_id)

    exactly = ec2_stopped.scan(ec2, REGION, now=stopped_at + timedelta(days=14), min_age_days=14)
    one_second_short = ec2_stopped.scan(
        ec2, REGION, now=stopped_at + timedelta(days=14) - timedelta(seconds=1), min_age_days=14
    )

    assert [f.resource_id for f in exactly] == [instance_id]
    assert one_second_short == []


def test_guardian_ignore_tag_is_respected(ec2):
    make_instance(ec2, tags={"guardian:ignore": "true"})

    assert ec2_stopped.scan(ec2, REGION, now=later(60), min_age_days=14) == []


def test_guardian_ignore_false_does_not_ignore(ec2):
    make_instance(ec2, tags={"guardian:ignore": "false"})

    assert len(ec2_stopped.scan(ec2, REGION, now=later(60), min_age_days=14)) == 1


def test_cost_adds_up_every_attached_volume(ec2):
    make_instance(
        ec2,
        volumes=[
            root_volume(size=20, volume_type="gp3"),
            {"DeviceName": "/dev/sdf", "Ebs": {"VolumeSize": 200, "VolumeType": "gp2"}},
        ],
    )

    (f,) = ec2_stopped.scan(ec2, REGION, now=later(30), min_age_days=14)

    gp3_root = estimate_ebs_monthly_cost("gp3", 20, REGION)
    gp2_data = estimate_ebs_monthly_cost("gp2", 200, REGION)
    expected = round(gp3_root + gp2_data, 2)
    assert f.estimated_monthly_cost_usd == expected
    assert f.evidence["volume_gib_total"] == 220
    assert len(f.evidence["volume_ids"]) == 2


def test_findings_sorted_by_cost_descending(ec2):
    make_instance(ec2, volumes=[root_volume(size=8)])
    big = make_instance(ec2, volumes=[root_volume(size=500)])
    make_instance(ec2, volumes=[root_volume(size=50)])

    findings = ec2_stopped.scan(ec2, REGION, now=later(30), min_age_days=14)

    assert findings[0].resource_id == big
    costs = [f.estimated_monthly_cost_usd for f in findings]
    assert costs == sorted(costs, reverse=True)


def test_name_tag_is_shown_in_the_summary_and_long_names_are_cut(ec2):
    make_instance(ec2, tags={"Name": "old-web-server-" + "x" * 100})

    (f,) = ec2_stopped.scan(ec2, REGION, now=later(30), min_age_days=14)

    assert '"old-web-server-' in f.summary
    assert "x" * 41 not in f.summary


def test_safe_name_drops_control_characters_but_keeps_other_scripts():
    # Real AWS rejects control characters in tags, so this is checked directly.
    assert ec2_stopped._safe_name({"Name": "old\nweb\x07 server"}) == "oldweb server"
    assert ec2_stopped._safe_name({"Name": "सर्वर-1"}) == "सर्वर-1"
    assert ec2_stopped._safe_name({}) == ""
    assert len(ec2_stopped._safe_name({"Name": "y" * 500})) == ec2_stopped._NAME_MAX_CHARS


# --- instances whose stop time cannot be determined --------------------------


@pytest.fixture
def no_stop_timestamp(monkeypatch):
    """Simulate stops that carry no timestamp (e.g. shutdown from inside the OS)."""
    monkeypatch.setattr(ec2_stopped, "parse_stop_time", lambda _reason: None)


def test_unknown_stop_time_is_skipped_if_launched_too_recently(ec2, no_stop_timestamp):
    make_instance(ec2)

    # Launched moments ago, so it cannot have been stopped for 14 days.
    assert ec2_stopped.scan(ec2, REGION, min_age_days=14) == []


def test_unknown_stop_time_is_reported_but_marked_as_unknown(ec2, no_stop_timestamp):
    instance_id = make_instance(ec2)

    (f,) = ec2_stopped.scan(ec2, REGION, now=later(60), min_age_days=14)

    assert f.resource_id == instance_id
    assert f.evidence["stop_time_known"] is False
    assert f.evidence["stopped_at"] is None
    assert f.evidence["days_stopped"] is None
    assert "stop time unknown" in f.summary
    assert "stopped None" not in f.summary


# --- handler integration -----------------------------------------------------


def test_handler_reports_stopped_instance_and_honours_the_env_setting(ec2, monkeypatch):
    import handler

    instance_id = make_instance(ec2, volumes=[root_volume(size=100)])

    # Default threshold is 14 days, so a fresh stop is not reported.
    assert handler.lambda_handler({}, None)["findings"] == 0

    monkeypatch.setenv("STOPPED_MIN_AGE_DAYS", "0")
    result = handler.lambda_handler({}, None)

    assert result["findings"] == 1
    assert result["errors"] == []
    findings, _errors, succeeded = handler.run_scanners(ec2, REGION, 3, 90, 0)
    assert [f.resource_id for f in findings] == [instance_id]
    assert ec2_stopped.CHECK_NAME in succeeded


def test_a_crash_in_this_scanner_does_not_hide_the_others(ec2, monkeypatch):
    import handler
    from scanners import ebs_unattached

    ec2.create_volume(AvailabilityZone="ap-south-1a", Size=10, VolumeType="gp3")

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(ec2_stopped, "scan", boom)

    findings, errors, succeeded = handler.run_scanners(ec2, REGION, 0)

    assert [f.check for f in findings] == [ebs_unattached.CHECK_NAME]
    assert errors == [f"{ec2_stopped.CHECK_NAME}: RuntimeError"]
    assert ec2_stopped.CHECK_NAME not in succeeded
    assert "secret internal detail" not in "".join(errors)
