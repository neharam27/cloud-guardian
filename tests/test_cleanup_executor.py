"""The executor Lambda is the only thing that can act. It trusts the database, not the message."""

import pytest
from helpers import (
    backups,
    finding_id,
    make_topic_with_queue,
    make_volume,
    read_emails,
    volume_exists,
)

import cleanup_executor
from remediation import ebs_delete, executor
from remediation.approvals import STATUS_CLAIMED, STATUS_PENDING, ApprovalStore, hash_token

REGION = "ap-south-1"
NO_WAIT = {"sleep": lambda _seconds: None}


@pytest.fixture(autouse=True)
def lambda_env(monkeypatch):
    monkeypatch.setenv("APPROVALS_TABLE", "guardian-approvals")
    monkeypatch.setenv("MIN_AGE_DAYS", "0")
    monkeypatch.delenv("DRY_RUN", raising=False)
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)


@pytest.fixture
def store(approvals_table):
    return ApprovalStore(approvals_table)


def approved(store, volume_id):
    """Create an approval and claim it, the way the approver Lambda would."""
    token = store.create(finding_id(volume_id), ebs_delete.ACTION)
    store.claim(token)
    return hash_token(token)


def pending(store, volume_id):
    return hash_token(store.create(finding_id(volume_id), ebs_delete.ACTION))


def run_by_id(ec2, store, approval_id, **overrides):
    kwargs = {"ec2": ec2, "store": store, "region": REGION, "min_age_days": 0, **NO_WAIT}
    kwargs.update(overrides)
    return executor.run_by_id(approval_id, **kwargs)


# --- run_by_id: trust the database --------------------------------------------


def test_a_real_run_requires_an_approval_that_was_really_claimed(ec2, store, approvals_table):
    volume = make_volume(ec2)
    approval_id = pending(store, volume)  # created, but nobody pressed the button

    result = run_by_id(ec2, store, approval_id, dry_run=False)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "not approved" in result.detail
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []
    (item,) = approvals_table.scan()["Items"]
    assert item["status"] == STATUS_PENDING


def test_an_unknown_approval_id_does_nothing(ec2, store):
    volume = make_volume(ec2)

    for bad in ["", "nope", "x" * 500, hash_token("never created")]:
        result = run_by_id(ec2, store, bad, dry_run=False)
        assert result.status == ebs_delete.STATUS_REFUSED

    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_a_claimed_approval_runs_once_even_if_the_message_is_delivered_twice(
    ec2, store, approvals_table
):
    volume = make_volume(ec2)
    approval_id = approved(store, volume)

    first = run_by_id(ec2, store, approval_id, dry_run=False)
    second = run_by_id(ec2, store, approval_id, dry_run=False)

    assert first.status == ebs_delete.STATUS_DONE
    assert second.status == ebs_delete.STATUS_REFUSED
    assert "already started or finished" in second.detail
    assert len(backups(ec2)) == 1
    (item,) = approvals_table.scan()["Items"]
    assert item["outcome"] == ebs_delete.STATUS_DONE


def test_an_approval_that_is_already_running_is_not_started_again(ec2, store):
    volume = make_volume(ec2)
    approval_id = approved(store, volume)
    assert store.begin(approval_id) is True  # another delivery got there first

    result = run_by_id(ec2, store, approval_id, dry_run=False)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_begin_succeeds_exactly_once_and_only_for_claimed_approvals(store):
    claimed = approved(store, "vol-0123456789abcdef0")
    unclaimed = pending(store, "vol-0123456789abcdef1")

    assert store.begin(unclaimed) is False
    assert store.begin(claimed) is True
    assert store.begin(claimed) is False


def test_dry_run_by_id_changes_nothing_and_leaves_no_outcome(ec2, store, approvals_table):
    volume = make_volume(ec2)
    approval_id = pending(store, volume)

    result = run_by_id(ec2, store, approval_id, dry_run=True)

    assert result.status == ebs_delete.STATUS_DRY_RUN
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []
    (item,) = approvals_table.scan()["Items"]
    assert item["status"] == STATUS_PENDING
    assert "outcome" not in item


# --- the Lambda entry point ---------------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "true", "TRUE", "0", "no", "off", "flase", " ", "1"])
def test_anything_but_the_word_false_means_dry_run(raw):
    assert cleanup_executor.is_dry_run(raw) is True


@pytest.mark.parametrize("raw", ["false", "FALSE", " False "])
def test_only_the_word_false_enables_real_actions(raw):
    assert cleanup_executor.is_dry_run(raw) is False


@pytest.mark.parametrize("raw", [None, "", "true", "0", "flase"])
def test_the_lambda_stays_dry_unless_explicitly_configured_live(
    ec2, store, monkeypatch, approvals_table, raw
):
    if raw is not None:
        monkeypatch.setenv("DRY_RUN", raw)
    volume = make_volume(ec2)
    approval_id = approved(store, volume)

    response = cleanup_executor.lambda_handler({"approval_id": approval_id}, None)

    assert response["dry_run"] is True
    assert response["status"] == ebs_delete.STATUS_DRY_RUN
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_the_message_cannot_switch_off_dry_run(ec2, store):
    volume = make_volume(ec2)
    approval_id = approved(store, volume)
    hostile = {"approval_id": approval_id, "dry_run": False, "DRY_RUN": "false", "live": True}

    response = cleanup_executor.lambda_handler(hostile, None)

    assert response["dry_run"] is True
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


@pytest.mark.parametrize("event", [None, {}, {"approval_id": 5}, {"approval_id": None}, [], "x"])
def test_a_message_without_a_usable_approval_id_does_nothing(ec2, monkeypatch, event):
    monkeypatch.setenv("DRY_RUN", "false")
    volume = make_volume(ec2)

    response = cleanup_executor.lambda_handler(event, None)

    assert response["status"] == ebs_delete.STATUS_REFUSED
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_live_run_backs_up_deletes_and_emails_the_outcome(ec2, store, monkeypatch, approvals_table):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    target = make_volume(ec2, size=5)
    bystander = make_volume(ec2)
    approval_id = approved(store, target)

    response = cleanup_executor.lambda_handler({"approval_id": approval_id}, None)

    assert response["status"] == ebs_delete.STATUS_DONE
    assert response["dry_run"] is False
    assert not volume_exists(ec2, target)
    assert volume_exists(ec2, bystander)
    ((snapshot, _tags),) = backups(ec2)
    assert snapshot["VolumeId"] == target

    (email,) = read_emails(sqs, queue_url)
    assert "Clean-up done" in email["Subject"]
    assert target in email["Subject"]
    assert snapshot["SnapshotId"] in email["Message"]
    (item,) = approvals_table.scan()["Items"]
    assert item["status"] == STATUS_CLAIMED
    assert item["outcome"] == ebs_delete.STATUS_DONE


def test_a_refused_live_run_is_emailed_too(ec2, store, monkeypatch):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    volume = make_volume(ec2)
    approval_id = approved(store, volume)
    ec2.create_tags(Resources=[volume], Tags=[{"Key": "guardian:ignore", "Value": "true"}])

    response = cleanup_executor.lambda_handler({"approval_id": approval_id}, None)

    assert response["status"] == ebs_delete.STATUS_REFUSED
    assert volume_exists(ec2, volume)
    (email,) = read_emails(sqs, queue_url)
    assert "refused" in email["Subject"]
    assert "guardian:ignore" in email["Message"]


def test_dry_runs_send_no_email(ec2, store, monkeypatch):
    topic_arn, sqs, queue_url = make_topic_with_queue()
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    volume = make_volume(ec2)
    approval_id = pending(store, volume)

    cleanup_executor.lambda_handler({"approval_id": approval_id}, None)

    assert read_emails(sqs, queue_url) == []


def test_a_broken_email_never_hides_the_result(ec2, store, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:does-not-exist")
    volume = make_volume(ec2)
    approval_id = approved(store, volume)

    response = cleanup_executor.lambda_handler({"approval_id": approval_id}, None)

    assert response["status"] == ebs_delete.STATUS_DONE
    assert not volume_exists(ec2, volume)
