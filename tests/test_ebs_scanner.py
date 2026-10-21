import json
from datetime import UTC, datetime, timedelta

import boto3

import handler
from scanners import ebs_unattached
from scanners.common import Finding
from scanners.pricing import estimate_ebs_monthly_cost

REGION = "ap-south-1"
AZ = "ap-south-1a"


def make_volume(ec2, size=10, volume_type="gp3", tags=None):
    kwargs = {"AvailabilityZone": AZ, "Size": size, "VolumeType": volume_type}
    if tags:
        kwargs["TagSpecifications"] = [
            {
                "ResourceType": "volume",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
    return ec2.create_volume(**kwargs)["VolumeId"]


# --- pricing -----------------------------------------------------------------


def test_cost_estimate_scales_with_size_and_region():
    assert estimate_ebs_monthly_cost("gp3", 100, "us-east-1") == 8.0
    assert estimate_ebs_monthly_cost("gp3", 100, "ap-south-1") == round(8.0 * 1.14, 2)
    assert estimate_ebs_monthly_cost("gp3", 100, "ap-southeast-2") == round(8.0 * 1.20, 2)


def test_unknown_volume_type_uses_fallback_not_zero():
    assert estimate_ebs_monthly_cost("mystery", 10, "us-east-1") > 0


# --- scanner -----------------------------------------------------------------


def test_finds_unattached_volume_with_cost_and_evidence(ec2):
    volume_id = make_volume(ec2, size=100, volume_type="gp3")

    findings = ebs_unattached.scan(ec2, REGION, min_age_days=0)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == volume_id
    assert f.estimated_monthly_cost_usd == estimate_ebs_monthly_cost("gp3", 100, REGION)
    assert f.evidence["size_gib"] == 100
    assert f.evidence["state"] == "available"
    assert f.severity in {"low", "medium", "high"}


def test_attached_volume_is_not_flagged(ec2):
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    instance_id = ec2.run_instances(ImageId=image_id, MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]
    volume_id = make_volume(ec2)
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdh")

    assert ebs_unattached.scan(ec2, REGION, min_age_days=0) == []


def test_guardian_ignore_tag_is_respected(ec2):
    make_volume(ec2, tags={"guardian:ignore": "true"})

    assert ebs_unattached.scan(ec2, REGION, min_age_days=0) == []


def test_guardian_ignore_false_does_not_ignore(ec2):
    make_volume(ec2, tags={"guardian:ignore": "false"})

    assert len(ebs_unattached.scan(ec2, REGION, min_age_days=0)) == 1


def test_recent_volumes_are_skipped_by_min_age(ec2):
    make_volume(ec2)

    assert ebs_unattached.scan(ec2, REGION, min_age_days=7) == []


def test_old_volumes_are_flagged_by_min_age(ec2):
    make_volume(ec2)
    future = datetime.now(UTC) + timedelta(days=30)

    findings = ebs_unattached.scan(ec2, REGION, now=future, min_age_days=7)

    assert len(findings) == 1
    assert findings[0].evidence["age_days"] >= 29


def test_findings_sorted_by_cost_descending(ec2):
    make_volume(ec2, size=5)
    big = make_volume(ec2, size=500)
    make_volume(ec2, size=50)

    findings = ebs_unattached.scan(ec2, REGION, min_age_days=0)

    assert findings[0].resource_id == big
    costs = [f.estimated_monthly_cost_usd for f in findings]
    assert costs == sorted(costs, reverse=True)


# --- handler -----------------------------------------------------------------


def test_handler_publishes_report_to_sns(ec2, monkeypatch):
    sns = boto3.client("sns", region_name=REGION)
    sqs = boto3.client("sqs", region_name=REGION)
    topic_arn = sns.create_topic(Name="guardian-test")["TopicArn"]
    queue_url = sqs.create_queue(QueueName="guardian-test-q")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    make_volume(ec2, size=200)
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    monkeypatch.setenv("MIN_AGE_DAYS", "0")

    result = handler.lambda_handler({}, None)

    assert result["findings"] == 1
    assert result["notified"] is True
    assert result["estimated_monthly_waste_usd"] > 0

    messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)["Messages"]
    body = json.loads(messages[0]["Body"])
    assert "Cloud Guardian" in body["Subject"]
    assert "read-only" in body["Message"]


def test_handler_sends_nothing_when_no_findings(ec2, monkeypatch):
    sns = boto3.client("sns", region_name=REGION)
    topic_arn = sns.create_topic(Name="guardian-test")["TopicArn"]
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)

    result = handler.lambda_handler({}, None)

    assert result == {
        "findings": 0,
        "estimated_monthly_waste_usd": 0,
        "notified": False,
        "errors": [],
    }


def test_handler_without_topic_does_not_crash(ec2, monkeypatch):
    make_volume(ec2)
    monkeypatch.setenv("MIN_AGE_DAYS", "0")

    result = handler.lambda_handler({}, None)

    assert result["findings"] == 1
    assert result["notified"] is False


def test_report_truncates_long_lists():
    findings = [
        Finding(
            check="ebs-unattached-volume",
            resource_id=f"vol-{i:05d}",
            resource_type="AWS::EC2::Volume",
            region=REGION,
            estimated_monthly_cost_usd=1.0,
            severity="low",
            recommendation="",
            summary="10 GiB gp3 volume, unattached",
        )
        for i in range(handler.MAX_ITEMS_IN_REPORT + 7)
    ]

    subject, body = handler.format_report(findings, REGION)

    assert len(subject) <= 100
    assert "and 7 more" in body
