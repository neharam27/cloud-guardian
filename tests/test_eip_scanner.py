import pytest
from helpers import make_topic_with_queue, read_email

import handler
from scanners import ebs_unattached, eip_unassociated
from scanners.pricing import estimate_public_ipv4_monthly_cost

REGION = "ap-south-1"


def allocate(ec2, tags=None):
    allocation_id = ec2.allocate_address(Domain="vpc")["AllocationId"]
    if tags:
        ec2.create_tags(
            Resources=[allocation_id],
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )
    return allocation_id


def launch_instance(ec2):
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    return ec2.run_instances(ImageId=image_id, MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]


# --- pricing -----------------------------------------------------------------


def test_public_ipv4_estimate_is_positive_and_small():
    assert 0 < estimate_public_ipv4_monthly_cost() < 10


# --- scanner -----------------------------------------------------------------


def test_flags_unassociated_elastic_ip_with_cost_and_evidence(ec2):
    allocation_id = allocate(ec2)

    findings = eip_unassociated.scan(ec2, REGION)

    assert len(findings) == 1
    f = findings[0]
    assert f.check == eip_unassociated.CHECK_NAME
    assert f.resource_id == allocation_id
    assert f.estimated_monthly_cost_usd == estimate_public_ipv4_monthly_cost()
    assert f.evidence["allocation_id"] == allocation_id
    assert f.evidence["public_ip"]
    assert f.evidence["age_known"] is False
    assert f.evidence["public_ip"] in f.summary


def test_associated_elastic_ip_is_not_flagged(ec2):
    allocation_id = allocate(ec2)
    instance_id = launch_instance(ec2)
    ec2.associate_address(InstanceId=instance_id, AllocationId=allocation_id)

    assert eip_unassociated.scan(ec2, REGION) == []


def test_guardian_ignore_tag_is_respected(ec2):
    allocate(ec2, tags={"guardian:ignore": "true"})

    assert eip_unassociated.scan(ec2, REGION) == []


def test_guardian_ignore_false_does_not_ignore(ec2):
    allocate(ec2, tags={"guardian:ignore": "false"})

    assert len(eip_unassociated.scan(ec2, REGION)) == 1


def test_only_the_unused_address_is_flagged(ec2):
    used = allocate(ec2)
    unused = allocate(ec2)
    ec2.associate_address(InstanceId=launch_instance(ec2), AllocationId=used)

    findings = eip_unassociated.scan(ec2, REGION)

    assert [f.resource_id for f in findings] == [unused]


def test_no_addresses_means_no_findings(ec2):
    assert eip_unassociated.scan(ec2, REGION) == []


# --- handler: multiple scanners ----------------------------------------------


def test_handler_reports_findings_from_both_scanners(ec2, monkeypatch):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    ec2.create_volume(AvailabilityZone="ap-south-1a", Size=20, VolumeType="gp3")
    allocate(ec2)
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    monkeypatch.setenv("MIN_AGE_DAYS", "0")

    result = handler.lambda_handler({}, None)

    assert result["findings"] == 2
    assert result["errors"] == []
    email = read_email(sqs, queue_url)
    assert "ebs-unattached-volume" in email["Message"]
    assert "eip-unassociated" in email["Message"]


def test_failing_scanner_does_not_hide_the_other_and_is_reported(ec2, monkeypatch):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    allocate(ec2)
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(ebs_unattached, "scan", boom)

    result = handler.lambda_handler({}, None)

    assert result["findings"] == 1
    assert result["errors"] == ["ebs-unattached-volume: RuntimeError"]
    email = read_email(sqs, queue_url)
    assert "Scanner errors" in email["Message"]
    assert "scanner error(s)" in email["Subject"]
    # The exception message must not leak into the email.
    assert "secret internal detail" not in email["Message"]


def test_scanner_error_alone_still_sends_an_email(ec2, monkeypatch):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)

    def boom(*args, **kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(eip_unassociated, "scan", boom)

    result = handler.lambda_handler({}, None)

    assert result["findings"] == 0
    assert result["notified"] is True
    assert "Scanner errors" in read_email(sqs, queue_url)["Message"]


@pytest.mark.parametrize("env_value", ["0", "5"])
def test_min_age_setting_does_not_affect_elastic_ips(ec2, monkeypatch, env_value):
    allocate(ec2)
    monkeypatch.setenv("MIN_AGE_DAYS", env_value)

    assert handler.lambda_handler({}, None)["findings"] == 1
