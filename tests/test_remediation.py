"""Safety tests for approval-gated clean-up.

Read these as the contract: the clean-up deletes exactly one volume, only after a
verified backup, only with a valid one-time approval, and refuses in every other case.
"""

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from helpers import backups, finding_id, make_volume, volume_exists

from remediation import ebs_delete, executor
from remediation.approvals import STATUS_CLAIMED, STATUS_PENDING, ApprovalStore
from scanners import ebs_unattached

REGION = "ap-south-1"
NO_WAIT = {"sleep": lambda _seconds: None}


# --- helpers -----------------------------------------------------------------


def run(ec2, volume_id, **overrides):
    kwargs = {"region": REGION, "dry_run": False, "min_age_days": 0, **NO_WAIT}
    kwargs.update(overrides)
    return ebs_delete.remediate(ec2, finding_id(volume_id), **kwargs)


@pytest.fixture
def store(approvals_table):
    return ApprovalStore(approvals_table)


def execute(ec2, store, token, **overrides):
    kwargs = {
        "ec2": ec2,
        "store": store,
        "region": REGION,
        "dry_run": False,
        "min_age_days": 0,
        **NO_WAIT,
    }
    kwargs.update(overrides)
    return executor.execute(token, **kwargs)


def client_error(code, message="secret detail"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


# --- the happy path ----------------------------------------------------------


def test_approved_cleanup_backs_up_then_deletes_exactly_one_volume(ec2, store, approvals_table):
    target = make_volume(ec2, size=5)
    bystanders = [make_volume(ec2), make_volume(ec2)]
    token = store.create(finding_id(target), ebs_delete.ACTION)

    deleted = []
    original = ec2.delete_volume
    ec2.delete_volume = lambda **kw: (deleted.append(kw["VolumeId"]), original(**kw))[1]

    result = execute(ec2, store, token)

    assert result.status == ebs_delete.STATUS_DONE
    assert deleted == [target]
    assert not volume_exists(ec2, target)
    assert all(volume_exists(ec2, v) for v in bystanders)

    ((snapshot, tags),) = backups(ec2)
    assert snapshot["VolumeId"] == target
    assert snapshot["State"] == "completed"
    assert snapshot["SnapshotId"] == result.snapshot_id
    assert tags["guardian:backup-of"] == target

    (item,) = approvals_table.scan()["Items"]
    assert item["status"] == STATUS_CLAIMED
    assert item["outcome"] == ebs_delete.STATUS_DONE


# --- dry run changes nothing -------------------------------------------------


def test_dry_run_is_the_default_and_changes_nothing(ec2):
    volume = make_volume(ec2)

    result = ebs_delete.remediate(ec2, finding_id(volume), region=REGION, min_age_days=0)

    assert result.status == ebs_delete.STATUS_DRY_RUN
    assert "nothing was changed" in result.detail
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_executor_dry_run_is_the_default_and_does_not_use_up_the_approval(
    ec2, store, approvals_table
):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), ebs_delete.ACTION)

    result = executor.execute(
        token, ec2=ec2, store=store, region=REGION, min_age_days=0, **NO_WAIT
    )

    assert result.status == ebs_delete.STATUS_DRY_RUN
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []
    (item,) = approvals_table.scan()["Items"]
    assert item["status"] == STATUS_PENDING
    assert "outcome" not in item

    # The same link still works for real afterwards.
    assert execute(ec2, store, token).status == ebs_delete.STATUS_DONE


# --- the approval is required, valid and single-use --------------------------


def test_the_same_approval_cannot_run_twice(ec2, store):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), ebs_delete.ACTION)

    first = execute(ec2, store, token)
    second = execute(ec2, store, token)

    assert first.status == ebs_delete.STATUS_DONE
    assert second.status == ebs_delete.STATUS_REFUSED
    assert "already used" in second.detail
    assert len(backups(ec2)) == 1


def test_an_expired_approval_does_nothing(ec2, store):
    volume = make_volume(ec2)
    start = datetime.now(UTC)
    token = store.create(finding_id(volume), ebs_delete.ACTION, start, ttl_seconds=60)

    result = execute(ec2, store, token, now=start + timedelta(hours=25))

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "expired" in result.detail
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


@pytest.mark.parametrize("dry_run", [True, False])
def test_unknown_or_tampered_tokens_do_nothing(ec2, store, dry_run):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), ebs_delete.ACTION)

    for bad in ["nope", "", token[:-1] + ("A" if token[-1] != "A" else "B")]:
        result = execute(ec2, store, bad, dry_run=dry_run)
        assert result.status == ebs_delete.STATUS_REFUSED

    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_an_approval_for_an_unknown_action_does_nothing(ec2, store, approvals_table):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), "terminate-everything")

    result = execute(ec2, store, token)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert result.detail == "unknown action"
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []
    (item,) = approvals_table.scan()["Items"]
    assert item["outcome"] == ebs_delete.STATUS_REFUSED


# --- only a well-formed volume in this region is in scope --------------------

OUT_OF_SCOPE = [
    "",
    "junk",
    "a#b",
    "ebs-unattached-volume#ap-south-1",
    "ebs-old-snapshot#ap-south-1#snap-0123456789abcdef0",
    "eip-unassociated#ap-south-1#eipalloc-0123456789abcdef0",
    "ebs-unattached-volume#us-east-1#vol-0123456789abcdef0",
    "ebs-unattached-volume#ap-south-1#i-0123456789abcdef0",
    "ebs-unattached-volume#ap-south-1#vol-0123456789abcdef0;DeleteAll",
    "ebs-unattached-volume#ap-south-1#vol-*",
    "ebs-unattached-volume#ap-south-1#vol-0123",
    "ebs-unattached-volume#ap-south-1#VOL-0123456789ABCDEF0",
    "ebs-unattached-volume#ap-south-1#vol-0123456789abcdef0#extra",
    None,
]


@pytest.mark.parametrize("bad_id", OUT_OF_SCOPE)
def test_out_of_scope_targets_are_refused_and_touch_nothing(ec2, bad_id):
    bystander = make_volume(ec2)

    result = ebs_delete.remediate(
        ec2, bad_id, region=REGION, dry_run=False, min_age_days=0, **NO_WAIT
    )

    assert result.status == ebs_delete.STATUS_REFUSED
    assert volume_exists(ec2, bystander)
    assert backups(ec2) == []


def test_a_client_in_another_region_is_refused(ec2):
    volume = make_volume(ec2)
    other_region = boto3.client("ec2", region_name="us-east-1")

    result = run(other_region, volume)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "region" in result.detail
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


# --- the volume is re-checked at the moment of action ------------------------


def test_a_volume_that_got_attached_since_the_finding_is_refused(ec2):
    volume = make_volume(ec2)
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    instance_id = ec2.run_instances(ImageId=image_id, MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]
    ec2.attach_volume(VolumeId=volume, InstanceId=instance_id, Device="/dev/sdh")

    result = run(ec2, volume)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "attached" in result.detail
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_a_volume_tagged_ignore_after_approval_is_refused(ec2, store):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), ebs_delete.ACTION)
    ec2.create_tags(Resources=[volume], Tags=[{"Key": "guardian:ignore", "Value": "true"}])

    result = execute(ec2, store, token)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "guardian:ignore" in result.detail
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_a_volume_the_scanner_would_not_report_is_refused(ec2):
    volume = make_volume(ec2)  # brand new

    result = run(ec2, volume, min_age_days=7)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert volume_exists(ec2, volume)
    assert backups(ec2) == []


def test_a_volume_that_is_already_gone_is_not_an_error_and_makes_no_backup(ec2, store):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), ebs_delete.ACTION)
    ec2.delete_volume(VolumeId=volume)

    result = execute(ec2, store, token)

    assert result.status == ebs_delete.STATUS_ALREADY_GONE
    assert backups(ec2) == []


def test_a_change_during_the_backup_wait_is_caught_before_deleting(ec2, monkeypatch):
    volume = make_volume(ec2)

    def wait_then_someone_protects_the_volume(client, snapshot_id, **_kwargs):
        client.create_tags(Resources=[volume], Tags=[{"Key": "guardian:ignore", "Value": "true"}])
        return "completed"

    monkeypatch.setattr(ebs_delete, "wait_for_snapshot", wait_then_someone_protects_the_volume)

    result = run(ec2, volume)

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "guardian:ignore" in result.detail
    assert volume_exists(ec2, volume)
    assert len(backups(ec2)) == 1  # the backup is kept, harmlessly


# --- no verified backup, no deletion -----------------------------------------


def test_if_the_backup_cannot_be_created_nothing_is_deleted(ec2, monkeypatch):
    volume = make_volume(ec2)

    def refuse(**_kwargs):
        raise client_error("SnapshotLimitExceeded", "secret detail")

    monkeypatch.setattr(ec2, "create_snapshot", refuse)

    result = run(ec2, volume)

    assert result.status == ebs_delete.STATUS_FAILED
    assert "SnapshotLimitExceeded" in result.detail
    assert "secret detail" not in result.detail
    assert volume_exists(ec2, volume)


def test_if_the_backup_never_completes_nothing_is_deleted(ec2, monkeypatch):
    volume = make_volume(ec2)
    monkeypatch.setattr(ebs_delete, "snapshot_state", lambda _client, _snapshot_id: "pending")

    result = run(ec2, volume, max_wait_seconds=10)

    assert result.status == ebs_delete.STATUS_FAILED
    assert "did not complete" in result.detail
    assert result.snapshot_id
    assert volume_exists(ec2, volume)


def test_if_the_backup_errors_nothing_is_deleted(ec2, monkeypatch):
    volume = make_volume(ec2)
    monkeypatch.setattr(ebs_delete, "snapshot_state", lambda _client, _snapshot_id: "error")

    result = run(ec2, volume)

    assert result.status == ebs_delete.STATUS_FAILED
    assert volume_exists(ec2, volume)


def test_a_backup_of_a_different_volume_is_not_accepted(ec2):
    target_id = make_volume(ec2)
    other_id = make_volume(ec2)
    wrong_snapshot = ec2.create_snapshot(VolumeId=other_id)["SnapshotId"]
    target = ebs_delete.Target(volume_id=target_id, region=REGION)

    result = ebs_delete.delete_after_backup(
        ec2, target, wrong_snapshot, datetime.now(UTC), min_age_days=0
    )

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "not a backup of this volume" in result.detail
    assert volume_exists(ec2, target_id)


def test_a_backup_that_is_not_completed_is_not_accepted(ec2, monkeypatch):
    volume = make_volume(ec2)
    snapshot_id = ec2.create_snapshot(VolumeId=volume)["SnapshotId"]
    real_describe = ec2.describe_snapshots

    def still_pending(**kwargs):
        response = real_describe(**kwargs)
        for snap in response["Snapshots"]:
            snap["State"] = "pending"
        return response

    monkeypatch.setattr(ec2, "describe_snapshots", still_pending)
    target = ebs_delete.Target(volume_id=volume, region=REGION)

    result = ebs_delete.delete_after_backup(
        ec2, target, snapshot_id, datetime.now(UTC), min_age_days=0
    )

    assert result.status == ebs_delete.STATUS_REFUSED
    assert "not completed" in result.detail
    assert volume_exists(ec2, volume)


def test_a_missing_backup_is_not_accepted(ec2):
    volume = make_volume(ec2)
    target = ebs_delete.Target(volume_id=volume, region=REGION)

    result = ebs_delete.delete_after_backup(
        ec2, target, "snap-0123456789abcdef0", datetime.now(UTC), min_age_days=0
    )

    assert result.status == ebs_delete.STATUS_REFUSED
    assert volume_exists(ec2, volume)


# --- failures are reported honestly ------------------------------------------


def test_a_failed_delete_is_reported_and_the_backup_is_kept(ec2, monkeypatch):
    volume = make_volume(ec2)

    def refuse(**_kwargs):
        raise client_error("VolumeInUse", "secret detail")

    monkeypatch.setattr(ec2, "delete_volume", refuse)

    result = run(ec2, volume)

    assert result.status == ebs_delete.STATUS_FAILED
    assert "VolumeInUse" in result.detail
    assert "secret detail" not in result.detail
    assert volume_exists(ec2, volume)
    assert len(backups(ec2)) == 1


def test_an_unexpected_error_is_recorded_without_leaking_its_text(
    ec2, store, approvals_table, monkeypatch
):
    volume = make_volume(ec2)
    token = store.create(finding_id(volume), ebs_delete.ACTION)

    def explode(*_args, **_kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(ebs_delete, "remediate", explode)

    result = execute(ec2, store, token)

    assert result.status == ebs_delete.STATUS_FAILED
    assert "RuntimeError" in result.detail
    assert "secret internal detail" not in result.detail
    assert volume_exists(ec2, volume)
    (item,) = approvals_table.scan()["Items"]
    assert item["status"] == STATUS_CLAIMED  # used up on purpose: a human asks again
    assert item["outcome"] == ebs_delete.STATUS_FAILED
    assert "secret internal detail" not in item["detail"]


# --- the scanner and the clean-up share one rule -----------------------------


def test_evaluate_volume_is_the_single_rule_for_wasted(ec2):
    volume_id = make_volume(ec2)
    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    now = datetime.now(UTC) + timedelta(days=1)

    assert ebs_unattached.evaluate_volume(volume, REGION, now, 0) is not None
    assert ebs_unattached.evaluate_volume({**volume, "State": "in-use"}, REGION, now, 0) is None
    assert (
        ebs_unattached.evaluate_volume({**volume, "Attachments": [{"x": 1}]}, REGION, now, 0)
        is None
    )
    tagged = {**volume, "Tags": [{"Key": "guardian:ignore", "Value": "true"}]}
    assert ebs_unattached.evaluate_volume(tagged, REGION, now, 0) is None
