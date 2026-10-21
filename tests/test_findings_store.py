import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from botocore.exceptions import ClientError
from helpers import make_topic_with_queue, read_email, read_emails

import handler
from findings_store import FindingStore, finding_key
from scanners import ebs_unattached
from scanners.common import Finding

REGION = "ap-south-1"
T0 = datetime(2026, 10, 1, 8, 30, tzinfo=UTC)
T1 = T0 + timedelta(days=1)
T2 = T0 + timedelta(days=2)
EBS = "ebs-unattached-volume"
EIP = "eip-unassociated"


def make_finding(check=EBS, resource_id="vol-1", cost=1.5, region=REGION):
    return Finding(
        check=check,
        resource_id=resource_id,
        resource_type="AWS::EC2::Volume",
        region=region,
        estimated_monthly_cost_usd=cost,
        severity="low",
        recommendation="delete it",
        summary=f"{resource_id} summary",
        evidence={"size_gib": 10},
    )


def item_for(table, finding):
    return table.get_item(Key={"finding_id": finding_key(finding)}).get("Item")


# --- store: recording --------------------------------------------------------


def test_new_finding_is_stored_as_open(findings_table):
    store = FindingStore(findings_table)
    f = make_finding()

    diff = store.record_scan([f], {EBS}, REGION, T0)

    assert diff.new == [f]
    assert diff.still_open == [] and diff.resolved == []
    item = item_for(findings_table, f)
    assert item["status"] == "open"
    assert item["first_seen"] == T0.isoformat()
    assert item["estimated_monthly_cost_usd"] == Decimal("1.5")
    assert json.loads(item["evidence"]) == {"size_gib": 10}
    assert "notified_at" not in item


def test_unannounced_finding_keeps_being_reported_as_new(findings_table):
    store = FindingStore(findings_table)
    f = make_finding()
    store.record_scan([f], {EBS}, REGION, T0)

    # The email for the first scan never went out, so nothing was marked notified.
    diff = store.record_scan([f], {EBS}, REGION, T1)

    assert diff.new == [f]
    assert item_for(findings_table, f)["first_seen"] == T0.isoformat()


def test_announced_finding_becomes_still_open_and_is_refreshed(findings_table):
    store = FindingStore(findings_table)
    store.record_scan([make_finding(cost=1.5)], {EBS}, REGION, T0)
    store.mark_notified([make_finding()], T0)

    diff = store.record_scan([make_finding(cost=2.5)], {EBS}, REGION, T1)

    assert diff.new == []
    assert [f.resource_id for f in diff.still_open] == ["vol-1"]
    item = item_for(findings_table, make_finding())
    assert item["first_seen"] == T0.isoformat()
    assert item["last_seen"] == T1.isoformat()
    assert item["estimated_monthly_cost_usd"] == Decimal("2.5")


# --- store: resolving --------------------------------------------------------


def test_missing_finding_is_marked_resolved(findings_table):
    store = FindingStore(findings_table)
    f = make_finding()
    store.record_scan([f], {EBS}, REGION, T0)
    store.mark_notified([f], T0)

    diff = store.record_scan([], {EBS}, REGION, T1)

    assert [r["resource_id"] for r in diff.resolved] == ["vol-1"]
    item = item_for(findings_table, f)
    assert item["status"] == "resolved"
    assert item["resolved_at"] == T1.isoformat()


def test_a_failed_scanner_never_resolves_its_findings(findings_table):
    store = FindingStore(findings_table)
    f = make_finding()
    store.record_scan([f], {EBS}, REGION, T0)

    # The EBS scanner crashed this time: no findings AND not in succeeded_checks.
    diff = store.record_scan([], set(), REGION, T1)

    assert diff.resolved == []
    assert item_for(findings_table, f)["status"] == "open"


def test_only_successful_scanners_resolve(findings_table):
    store = FindingStore(findings_table)
    ebs = make_finding(check=EBS, resource_id="vol-1")
    eip = make_finding(check=EIP, resource_id="eipalloc-1")
    store.record_scan([ebs, eip], {EBS, EIP}, REGION, T0)

    diff = store.record_scan([], {EBS}, REGION, T1)

    assert [r["resource_id"] for r in diff.resolved] == ["vol-1"]
    assert item_for(findings_table, eip)["status"] == "open"


def test_other_regions_are_left_alone(findings_table):
    store = FindingStore(findings_table)
    elsewhere = make_finding(region="us-east-1")
    store.record_scan([elsewhere], {EBS}, "us-east-1", T0)

    diff = store.record_scan([], {EBS}, REGION, T1)

    assert diff.resolved == []
    assert item_for(findings_table, elsewhere)["status"] == "open"


def test_a_resolved_finding_that_returns_is_new_again(findings_table):
    store = FindingStore(findings_table)
    f = make_finding()
    store.record_scan([f], {EBS}, REGION, T0)
    store.mark_notified([f], T0)
    store.record_scan([], {EBS}, REGION, T1)

    diff = store.record_scan([f], {EBS}, REGION, T2)

    assert diff.new == [f]
    item = item_for(findings_table, f)
    assert item["status"] == "open"
    assert item["first_seen"] == T2.isoformat()
    assert "notified_at" not in item
    assert "resolved_at" not in item


# --- handler with the store --------------------------------------------------


def configure(monkeypatch, table, digest_today=False):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    weekday = datetime.now(UTC).weekday()
    monkeypatch.setenv("FINDINGS_TABLE", table.name)
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    monkeypatch.setenv("MIN_AGE_DAYS", "0")
    monkeypatch.setenv("DIGEST_WEEKDAY", str(weekday if digest_today else (weekday + 1) % 7))
    return sqs, queue_url


def make_volume(ec2):
    return ec2.create_volume(AvailabilityZone="ap-south-1a", Size=20, VolumeType="gp3")["VolumeId"]


def test_first_run_announces_and_second_run_is_silent(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table)
    volume_id = make_volume(ec2)

    first = handler.lambda_handler({}, None)
    email = read_email(sqs, queue_url)

    assert first["new"] == 1 and first["notified"] is True
    assert "New since the last report" in email["Message"]
    assert volume_id in email["Message"]

    second = handler.lambda_handler({}, None)

    assert second["findings"] == 1
    assert second["new"] == 0
    assert second["notified"] is False
    assert read_emails(sqs, queue_url) == []


def test_resolution_is_announced_once(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table)
    volume_id = make_volume(ec2)
    handler.lambda_handler({}, None)
    read_emails(sqs, queue_url)

    ec2.delete_volume(VolumeId=volume_id)
    third = handler.lambda_handler({}, None)
    email = read_email(sqs, queue_url)

    assert third["resolved"] == 1 and third["notified"] is True
    assert "Resolved since the last scan" in email["Message"]
    assert volume_id in email["Message"]

    fourth = handler.lambda_handler({}, None)

    assert fourth["notified"] is False


def test_digest_flag_lists_everything_that_is_still_open(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table)
    volume_id = make_volume(ec2)
    handler.lambda_handler({}, None)
    read_emails(sqs, queue_url)

    result = handler.lambda_handler({"digest": True}, None)
    email = read_email(sqs, queue_url)

    assert result["notified"] is True
    assert "Still open (weekly digest)" in email["Message"]
    assert volume_id in email["Message"]


def test_weekly_digest_day_sends_a_digest_without_any_flag(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table, digest_today=True)
    make_volume(ec2)
    handler.lambda_handler({}, None)
    read_emails(sqs, queue_url)

    result = handler.lambda_handler({}, None)

    assert result["notified"] is True
    assert "Still open (weekly digest)" in read_email(sqs, queue_url)["Message"]


def test_broken_store_falls_back_to_a_full_report(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table)
    volume_id = make_volume(ec2)

    def boom(*args, **kwargs):
        raise RuntimeError("table exploded")

    monkeypatch.setattr(FindingStore, "record_scan", boom)

    result = handler.lambda_handler({}, None)
    email = read_email(sqs, queue_url)

    assert result["errors"] == ["findings-store: RuntimeError"]
    assert result["new"] == 1
    assert volume_id in email["Message"]
    assert "Scanner errors" in email["Message"]


def test_failed_email_is_retried_on_the_next_run(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table)
    good_topic = handler.os.environ["SNS_TOPIC_ARN"]
    volume_id = make_volume(ec2)

    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:does-not-exist")
    with pytest.raises(ClientError):
        handler.lambda_handler({}, None)

    key = {"finding_id": f"{EBS}#{REGION}#{volume_id}"}
    item = findings_table.get_item(Key=key)["Item"]
    assert item["status"] == "open"
    assert "notified_at" not in item  # recorded, but never announced

    monkeypatch.setenv("SNS_TOPIC_ARN", good_topic)
    result = handler.lambda_handler({}, None)

    assert result["notified"] is True
    assert volume_id in read_email(sqs, queue_url)["Message"]
    assert "notified_at" in findings_table.get_item(Key=key)["Item"]


def test_a_crashed_scanner_does_not_resolve_findings_end_to_end(ec2, findings_table, monkeypatch):
    sqs, queue_url = configure(monkeypatch, findings_table)
    volume_id = make_volume(ec2)
    handler.lambda_handler({}, None)
    read_emails(sqs, queue_url)

    def boom(*args, **kwargs):
        raise RuntimeError("scanner crashed")

    with monkeypatch.context() as patch:
        patch.setattr(ebs_unattached, "scan", boom)
        crashed = handler.lambda_handler({}, None)

    assert crashed["resolved"] == 0
    assert crashed["errors"] == [f"{EBS}: RuntimeError"]
    key = {"finding_id": f"{EBS}#{REGION}#{volume_id}"}
    assert findings_table.get_item(Key=key)["Item"]["status"] == "open"

    # Once the scanner is healthy again and the volume really is gone, it resolves.
    ec2.delete_volume(VolumeId=volume_id)
    recovered = handler.lambda_handler({}, None)

    assert recovered["resolved"] == 1
