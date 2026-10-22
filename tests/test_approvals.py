from datetime import UTC, datetime, timedelta

import pytest

from remediation.approvals import (
    STATUS_CLAIMED,
    STATUS_PENDING,
    ApprovalStore,
    ExpiredApproval,
    UnknownApproval,
    UsedApproval,
    hash_token,
)

FINDING = "ebs-unattached-volume#ap-south-1#vol-0123456789abcdef0"
ACTION = "delete-unattached-volume"
BASE = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)  # whole seconds: expiry maths is exact


@pytest.fixture
def store(approvals_table):
    return ApprovalStore(approvals_table)


def only_item(table):
    (item,) = table.scan()["Items"]
    return item


def test_token_is_random_and_only_its_hash_is_stored(store, approvals_table):
    first = store.create(FINDING, ACTION, BASE)
    second = store.create(FINDING, ACTION, BASE)

    assert first != second
    assert len(first) >= 40

    items = approvals_table.scan()["Items"]
    assert {i["approval_id"] for i in items} == {hash_token(first), hash_token(second)}
    for item in items:
        assert first not in str(item)
        assert second not in str(item)


def test_a_valid_approval_can_be_claimed_once(store):
    token = store.create(FINDING, ACTION, BASE)

    approval = store.claim(token, BASE + timedelta(minutes=5))

    assert approval.finding_id == FINDING
    assert approval.action == ACTION
    assert approval.approval_id == hash_token(token)


def test_the_second_claim_is_refused(store, approvals_table):
    token = store.create(FINDING, ACTION, BASE)
    store.claim(token, BASE + timedelta(minutes=1))

    with pytest.raises(UsedApproval):
        store.claim(token, BASE + timedelta(minutes=2))

    assert only_item(approvals_table)["status"] == STATUS_CLAIMED


def test_an_expired_approval_is_refused_and_stays_unclaimed(store, approvals_table):
    token = store.create(FINDING, ACTION, BASE, ttl_seconds=60)

    with pytest.raises(ExpiredApproval):
        store.claim(token, BASE + timedelta(seconds=61))

    assert only_item(approvals_table)["status"] == STATUS_PENDING


def test_expiry_boundary_is_exact(store):
    token = store.create(FINDING, ACTION, BASE, ttl_seconds=60)

    with pytest.raises(ExpiredApproval):
        store.claim(token, BASE + timedelta(seconds=60))  # at expiry: too late
    assert store.claim(token, BASE + timedelta(seconds=59)).finding_id == FINDING


def test_unknown_and_tampered_tokens_are_refused(store):
    token = store.create(FINDING, ACTION, BASE)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    for bad in ["nope", "", tampered, token + "x", "x" * 5000]:
        with pytest.raises(UnknownApproval):
            store.claim(bad, BASE)

    # Failed attempts did not use up the real approval.
    assert store.claim(token, BASE).finding_id == FINDING


def test_peek_checks_without_using_the_approval_up(store):
    token = store.create(FINDING, ACTION, BASE)

    assert store.peek(token, BASE).finding_id == FINDING
    assert store.peek(token, BASE).finding_id == FINDING
    store.claim(token, BASE)  # still claimable after peeking

    with pytest.raises(UsedApproval):
        store.peek(token, BASE)


def test_peek_refuses_expired_and_unknown(store):
    token = store.create(FINDING, ACTION, BASE, ttl_seconds=10)

    with pytest.raises(ExpiredApproval):
        store.peek(token, BASE + timedelta(seconds=11))
    with pytest.raises(UnknownApproval):
        store.peek("nope", BASE)
    with pytest.raises(UnknownApproval):
        store.peek("x" * 5000, BASE)


def test_messages_shown_to_the_clicker_do_not_leak_details(store):
    token = store.create(FINDING, ACTION, BASE, ttl_seconds=10)
    store.claim(token, BASE)

    for exc in (UnknownApproval, ExpiredApproval, UsedApproval):
        assert exc.reason
        assert "vol-" not in exc.reason
        assert "ebs" not in exc.reason.lower()


def test_finish_records_the_outcome_for_the_audit_trail(store, approvals_table):
    token = store.create(FINDING, ACTION, BASE)
    approval = store.claim(token, BASE)

    store.finish(approval, "done", "deleted vol-x; backup is snap-y", BASE)

    item = only_item(approvals_table)
    assert item["outcome"] == "done"
    assert item["detail"] == "deleted vol-x; backup is snap-y"
    assert item["finished_at"] == BASE.isoformat()


def test_spent_records_are_kept_past_expiry_for_ttl_cleanup(store, approvals_table):
    store.create(FINDING, ACTION, BASE, ttl_seconds=60)

    item = only_item(approvals_table)
    assert int(item["ttl"]) > int(item["expires_at"])
