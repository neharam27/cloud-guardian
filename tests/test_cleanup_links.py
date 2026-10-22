"""The scanner email carries one-time clean-up links, and must never be hurt by them."""

import re
from datetime import UTC, datetime

import pytest
from helpers import finding_id, make_topic_with_queue, make_volume, read_email, read_emails

import handler
from remediation import ebs_delete
from remediation.approvals import ApprovalStore

URL = "https://approver.example.invalid"
LINK = re.compile(r"https://approver\.example\.invalid/\?t=([A-Za-z0-9_-]+)")


@pytest.fixture
def setup(ec2, findings_table, approvals_table, monkeypatch):
    """A scan wired for findings history, email and clean-up links."""
    topic_arn, sqs, queue_url = make_topic_with_queue()
    weekday = datetime.now(UTC).weekday()
    monkeypatch.setenv("FINDINGS_TABLE", findings_table.name)
    monkeypatch.setenv("APPROVALS_TABLE", approvals_table.name)
    monkeypatch.setenv("APPROVER_URL", URL)
    monkeypatch.setenv("SNS_TOPIC_ARN", topic_arn)
    monkeypatch.setenv("MIN_AGE_DAYS", "0")
    monkeypatch.setenv("DIGEST_WEEKDAY", str((weekday + 1) % 7))  # never "today"
    return sqs, queue_url, ApprovalStore(approvals_table)


def tokens_in(email):
    return LINK.findall(email["Message"])


def test_a_new_unattached_volume_gets_a_working_one_time_link(ec2, setup):
    sqs, queue_url, store = setup
    volume = make_volume(ec2)

    handler.lambda_handler({}, None)

    email = read_email(sqs, queue_url)
    (token,) = tokens_in(email)
    approval = store.peek(token)
    assert approval.finding_id == finding_id(volume)
    assert approval.action == ebs_delete.ACTION
    assert "work once and expire in 24 hours" in email["Message"]
    assert "do not forward" in email["Message"]


def test_the_link_leads_to_the_confirmation_page_not_straight_to_an_action(ec2, setup):
    sqs, queue_url, _store = setup
    make_volume(ec2)

    handler.lambda_handler({}, None)

    body = read_email(sqs, queue_url)["Message"]
    assert "nothing happens until you press" in body


def test_without_the_settings_the_email_is_exactly_as_before(ec2, setup, monkeypatch):
    sqs, queue_url, _store = setup
    monkeypatch.delenv("APPROVALS_TABLE")
    monkeypatch.delenv("APPROVER_URL")
    make_volume(ec2)

    handler.lambda_handler({}, None)

    body = read_email(sqs, queue_url)["Message"]
    assert "Clean up" not in body
    assert "?t=" not in body
    assert "expire in 24 hours" not in body


def test_only_unattached_volumes_get_links(ec2, setup):
    sqs, queue_url, _store = setup
    make_volume(ec2)
    ec2.allocate_address(Domain="vpc")  # an Elastic IP finding has no clean-up action

    handler.lambda_handler({}, None)

    email = read_email(sqs, queue_url)
    assert "eip-unassociated" in email["Message"]
    assert len(tokens_in(email)) == 1


def test_a_failure_to_make_links_never_breaks_the_scan(ec2, setup, approvals_table):
    sqs, queue_url, _store = setup
    make_volume(ec2)
    approvals_table.delete()

    result = handler.lambda_handler({}, None)

    assert result["notified"] is True
    assert result["errors"] == []
    email = read_email(sqs, queue_url)
    assert "ebs-unattached-volume" in email["Message"]
    assert "?t=" not in email["Message"]
    assert "expire in 24 hours" not in email["Message"]


def test_a_quiet_scan_makes_no_links(ec2, setup, approvals_table):
    sqs, queue_url, _store = setup
    make_volume(ec2)
    handler.lambda_handler({}, None)
    read_emails(sqs, queue_url)
    before = approvals_table.scan()["Count"]

    second = handler.lambda_handler({}, None)

    assert second["notified"] is False
    assert approvals_table.scan()["Count"] == before == 1


def test_the_weekly_digest_gets_fresh_working_links_for_still_open_volumes(ec2, setup):
    sqs, queue_url, store = setup
    volume = make_volume(ec2)
    handler.lambda_handler({}, None)
    (first_token,) = tokens_in(read_email(sqs, queue_url))

    handler.lambda_handler({"digest": True}, None)

    (digest_token,) = tokens_in(read_email(sqs, queue_url))
    assert digest_token != first_token
    assert store.peek(digest_token).finding_id == finding_id(volume)


def test_tokens_are_only_made_for_findings_that_are_actually_listed(ec2, setup, approvals_table):
    sqs, queue_url, _store = setup
    for _ in range(handler.MAX_ITEMS_IN_REPORT + 5):
        make_volume(ec2, size=1)

    handler.lambda_handler({}, None)

    email = read_email(sqs, queue_url)
    assert len(tokens_in(email)) == handler.MAX_ITEMS_IN_REPORT
    assert approvals_table.scan()["Count"] == handler.MAX_ITEMS_IN_REPORT
    assert "and 5 more" in email["Message"]


def test_the_link_is_not_in_the_logs_or_the_return_value(ec2, setup, caplog):
    make_volume(ec2)

    with caplog.at_level("INFO"):
        result = handler.lambda_handler({}, None)

    assert "?t=" not in str(result)
    assert "?t=" not in caplog.text
