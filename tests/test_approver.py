"""The approver Lambda sits behind a public URL, so these tests are deliberately paranoid."""

import base64
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import pytest

import approver
from remediation import ebs_delete
from remediation.approvals import STATUS_CLAIMED, STATUS_PENDING, ApprovalStore

REGION = "ap-south-1"
VOLUME = "vol-0123456789abcdef0"
FINDING = f"ebs-unattached-volume#{REGION}#{VOLUME}"
ACTION = ebs_delete.ACTION


class FakeInvoker:
    """Stands in for the executor Lambda and records how it was called."""

    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result if result is not None else {"status": "dry_run", "detail": "WOULD DO"}
        self.error = error

    def __call__(self, approval_id, wait):
        self.calls.append((approval_id, wait))
        if self.error:
            raise self.error
        return self.result if wait else None


@pytest.fixture
def store(approvals_table):
    return ApprovalStore(approvals_table)


def get_event(token=None):
    return {
        "requestContext": {"http": {"method": "GET"}},
        "queryStringParameters": {"t": token} if token is not None else None,
        "isBase64Encoded": False,
    }


def post_event(token, *, in_body=True, encoded=False, extra=""):
    body = urlencode({"t": token}) + extra if in_body else ""
    if encoded:
        body = base64.b64encode(body.encode()).decode()
    return {
        "requestContext": {"http": {"method": "POST"}},
        "queryStringParameters": None if in_body else {"t": token},
        "body": body,
        "isBase64Encoded": encoded,
    }


def call(event, store, invoker, *, live):
    return approver.handle(event, store=store, invoke=invoker, live=live, region=REGION)


def only_item(table):
    (item,) = table.scan()["Items"]
    return item


# --- GET only ever shows a page ----------------------------------------------


def test_get_shows_a_confirmation_page_and_changes_nothing(store, approvals_table):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    response = call(get_event(token), store, invoker, live=True)

    assert response["statusCode"] == 200
    assert VOLUME in response["body"]
    assert REGION in response["body"]
    assert "<form method=post" in response["body"]
    assert invoker.calls == []
    assert only_item(approvals_table)["status"] == STATUS_PENDING


def test_link_prefetchers_cannot_use_up_an_approval(store, approvals_table):
    """Email scanners open links. Opening must never act, however often it happens."""
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    for _ in range(5):
        assert call(get_event(token), store, invoker, live=True)["statusCode"] == 200

    assert invoker.calls == []
    assert only_item(approvals_table)["status"] == STATUS_PENDING
    assert call(post_event(token), store, invoker, live=True)["statusCode"] == 200
    assert len(invoker.calls) == 1


@pytest.mark.parametrize("token", [None, "", "nope", "x" * 5000])
def test_get_with_a_missing_or_unknown_token_is_refused_without_details(store, token):
    store.create(FINDING, ACTION)

    response = call(get_event(token), store, FakeInvoker(), live=True)

    assert response["statusCode"] == 400
    assert VOLUME not in response["body"]


def test_get_for_an_expired_or_used_approval_says_so(store):
    start = datetime.now(UTC)
    expired = store.create(FINDING, ACTION, start, ttl_seconds=60)
    used = store.create(FINDING, ACTION, start)
    store.claim(used, start)

    late = start + timedelta(hours=2)
    assert "expired" in approver.handle(
        get_event(expired), store=store, invoke=FakeInvoker(), live=True, region=REGION, now=late
    )["body"]
    assert "already used" in call(get_event(used), store, FakeInvoker(), live=True)["body"]


def test_page_offers_the_dry_run_button_in_dry_run_mode(store):
    token = store.create(FINDING, ACTION)

    body = call(get_event(token), store, FakeInvoker(), live=False)["body"]

    assert "DRY RUN" in body
    assert "Show what would happen" in body
    assert "Back up and delete" not in body


# --- POST in live mode: claim once, hand over --------------------------------


def test_post_claims_the_approval_and_starts_the_executor_once(store, approvals_table):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    response = call(post_event(token), store, invoker, live=True)

    assert response["statusCode"] == 200
    assert "Approved" in response["body"]
    assert only_item(approvals_table)["status"] == STATUS_CLAIMED
    assert invoker.calls == [(only_item(approvals_table)["approval_id"], False)]


def test_the_executor_is_never_given_the_secret_token(store):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    call(post_event(token), store, invoker, live=True)

    for approval_id, _wait in invoker.calls:
        assert approval_id != token
        assert token not in approval_id


def test_a_second_press_does_not_start_a_second_clean_up(store):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    first = call(post_event(token), store, invoker, live=True)
    second = call(post_event(token), store, invoker, live=True)

    assert first["statusCode"] == 200
    assert second["statusCode"] == 400
    assert "already used" in second["body"]
    assert len(invoker.calls) == 1


def test_an_expired_approval_cannot_be_pressed(store):
    start = datetime.now(UTC)
    token = store.create(FINDING, ACTION, start, ttl_seconds=60)
    invoker = FakeInvoker()

    response = approver.handle(
        post_event(token),
        store=store,
        invoke=invoker,
        live=True,
        region=REGION,
        now=start + timedelta(hours=2),
    )

    assert response["statusCode"] == 400
    assert invoker.calls == []


def test_if_the_executor_cannot_be_started_the_failure_is_recorded_not_leaked(
    store, approvals_table
):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker(error=RuntimeError("secret internal detail"))

    response = call(post_event(token), store, invoker, live=True)

    assert response["statusCode"] == 500
    assert "secret internal detail" not in response["body"]
    assert "Nothing was deleted" in response["body"]
    item = only_item(approvals_table)
    assert item["status"] == STATUS_CLAIMED  # used up on purpose
    assert item["outcome"] == ebs_delete.STATUS_FAILED


# --- POST in dry-run mode: ask, do not consume -------------------------------


def test_dry_run_post_shows_the_result_and_does_not_use_up_the_approval(store, approvals_table):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker(result={"status": "dry_run", "detail": "would snapshot vol-x"})

    response = call(post_event(token), store, invoker, live=False)

    assert response["statusCode"] == 200
    assert "would snapshot vol-x" in response["body"]
    assert "Nothing was changed" in response["body"]
    assert only_item(approvals_table)["status"] == STATUS_PENDING
    assert invoker.calls == [(only_item(approvals_table)["approval_id"], True)]
    # Still usable afterwards.
    assert call(post_event(token), store, FakeInvoker(), live=False)["statusCode"] == 200


def test_a_failed_dry_run_is_reported_without_details(store, approvals_table):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker(error=RuntimeError("secret internal detail"))

    response = call(post_event(token), store, invoker, live=False)

    assert response["statusCode"] == 500
    assert "secret internal detail" not in response["body"]
    assert only_item(approvals_table)["status"] == STATUS_PENDING


# --- the token must come from the button, in the body ------------------------


def test_post_ignores_a_token_that_is_only_in_the_url(store, approvals_table):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    response = call(post_event(token, in_body=False), store, invoker, live=True)

    assert response["statusCode"] == 400
    assert invoker.calls == []
    assert only_item(approvals_table)["status"] == STATUS_PENDING


def test_post_accepts_a_base64_encoded_body(store):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    response = call(post_event(token, encoded=True), store, invoker, live=True)

    assert response["statusCode"] == 200
    assert len(invoker.calls) == 1


def test_an_oversized_or_garbled_body_is_refused_before_anything_happens(store, approvals_table):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()

    huge = call(post_event(token, extra="&junk=" + "x" * 5000), store, invoker, live=True)
    garbled = call(
        {
            "requestContext": {"http": {"method": "POST"}},
            "body": "!!!not base64!!!",
            "isBase64Encoded": True,
        },
        store,
        invoker,
        live=True,
    )

    assert huge["statusCode"] == 413
    assert garbled["statusCode"] == 413
    assert invoker.calls == []
    assert only_item(approvals_table)["status"] == STATUS_PENDING


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", ""])
def test_other_methods_are_refused(store, method):
    token = store.create(FINDING, ACTION)
    invoker = FakeInvoker()
    event = {"requestContext": {"http": {"method": method}}, "queryStringParameters": {"t": token}}

    response = call(event, store, invoker, live=True)

    assert response["statusCode"] == 405
    assert response["headers"]["Allow"] == "GET, POST"
    assert invoker.calls == []


# --- only supported actions are ever offered ---------------------------------


@pytest.mark.parametrize(
    ("finding", "action"),
    [
        (FINDING, "terminate-everything"),
        ("ebs-old-snapshot#ap-south-1#snap-0123456789abcdef0", ACTION),
        (f"ebs-unattached-volume#us-east-1#{VOLUME}", ACTION),
        ("ebs-unattached-volume#ap-south-1#vol-*", ACTION),
    ],
)
def test_unsupported_approvals_get_no_button_and_cannot_be_pressed(
    store, approvals_table, finding, action
):
    token = store.create(finding, action)
    invoker = FakeInvoker()

    page = call(get_event(token), store, invoker, live=True)
    press = call(post_event(token), store, invoker, live=True)

    assert page["statusCode"] == 400
    assert "<form" not in page["body"]
    assert press["statusCode"] == 400
    assert invoker.calls == []
    assert only_item(approvals_table)["status"] == STATUS_PENDING  # not even claimed


def test_nothing_from_the_database_can_inject_markup_into_the_page(store):
    token = store.create("ebs-unattached-volume#ap-south-1#<script>alert(1)</script>", ACTION)

    body = call(get_event(token), store, FakeInvoker(), live=True)["body"]

    assert "<script>" not in body


def test_the_token_is_escaped_where_it_is_echoed_into_the_form(store):
    token = store.create(FINDING, ACTION)

    body = call(get_event(token), store, FakeInvoker(), live=True)["body"]

    assert f'value="{token}"' in body  # url-safe base64 needs no escaping, and is quoted


# --- every response carries the protective headers ---------------------------


@pytest.mark.parametrize("live", [True, False])
def test_security_headers_are_on_every_kind_of_response(store, live):
    token = store.create(FINDING, ACTION)
    responses = [
        call(get_event(token), store, FakeInvoker(), live=live),
        call(get_event("nope"), store, FakeInvoker(), live=live),
        call(post_event("nope"), store, FakeInvoker(), live=live),
        call({"requestContext": {"http": {"method": "PUT"}}}, store, FakeInvoker(), live=live),
    ]
    for response in responses:
        headers = response["headers"]
        assert headers["Cache-Control"] == "no-store"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        assert headers["Content-Type"].startswith("text/html")


# --- wiring ------------------------------------------------------------------


class StubLambdaClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class Payload:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data


def test_invoker_sends_only_the_approval_id():
    client = StubLambdaClient({"StatusCode": 202})

    approver.make_invoker(client, "cleanup-fn")("abc123", False)

    (call_args,) = client.calls
    assert call_args["FunctionName"] == "cleanup-fn"
    assert call_args["InvocationType"] == "Event"
    assert json.loads(call_args["Payload"]) == {"approval_id": "abc123"}


def test_invoker_waits_for_and_returns_a_dry_run_result():
    payload = Payload(json.dumps({"status": "dry_run", "detail": "x"}).encode())
    client = StubLambdaClient({"StatusCode": 200, "Payload": payload})

    result = approver.make_invoker(client, "cleanup-fn")("abc123", True)

    assert result == {"status": "dry_run", "detail": "x"}
    assert client.calls[0]["InvocationType"] == "RequestResponse"


def test_invoker_raises_if_the_executor_errors_or_is_not_accepted():
    errored = StubLambdaClient({"StatusCode": 200, "FunctionError": "Unhandled", "Payload": None})
    refused = StubLambdaClient({"StatusCode": 500})

    with pytest.raises(RuntimeError):
        approver.make_invoker(errored, "f")("abc", True)
    with pytest.raises(RuntimeError):
        approver.make_invoker(refused, "f")("abc", False)


def test_an_unexpected_crash_shows_a_generic_page(monkeypatch):
    monkeypatch.setenv("APPROVALS_TABLE", "x")
    monkeypatch.setenv("EXECUTOR_FUNCTION", "y")

    def explode(*_args, **_kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(approver, "handle", explode)

    response = approver.lambda_handler({}, None)

    assert response["statusCode"] == 500
    assert "secret internal detail" not in response["body"]
