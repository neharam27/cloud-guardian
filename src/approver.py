"""Lambda behind a public URL: show an approval page, and act on a button press.

Why two steps (GET page, then POST button)? Email security tools and chat apps
"pre-fetch" links to scan them. If opening the link did the work, a scanner could delete
your volume. So GET only ever shows a confirmation page and changes nothing. Only a POST
(the button) acts, and the token must come in the POST body, never the URL.

This Lambda has NO permission to touch EC2. It can only read/claim approvals and start
the executor Lambda, which is where any write permission lives.

Modes (CLEANUP_MODE):
  dry_run (default)  the button does NOT use the approval up; it asks the executor for a
                     dry run and shows what would have happened.
  live               the button claims the approval (once only) and starts the executor,
                     which emails the outcome.
"""

from __future__ import annotations

import base64
import html
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs

import boto3

from remediation import ebs_delete
from remediation.approvals import Approval, ApprovalError, ApprovalStore
from remediation.executor import KNOWN_ACTIONS

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_BODY_BYTES = 2048

# invoke(approval_id, wait) -> executor result dict if wait else None
Invoker = Callable[[str, bool], dict[str, Any] | None]

_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
}

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;"
    "line-height:1.5}h1{font-size:1.3rem}.box{border:1px solid #8884;border-radius:8px;"
    "padding:1rem;margin:1rem 0}.warn{font-weight:600}button{font-size:1rem;padding:.6rem 1.2rem;"
    "border-radius:6px;border:0;background:#b3261e;color:#fff;cursor:pointer}"
    "button.safe{background:#1a56db}small{opacity:.7}"
)


def _page(status: int, title: str, body_html: str, extra_headers: dict[str, str] | None = None):
    document = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><h1>{html.escape(title)}</h1>{body_html}"
        "<p><small>Cloud Guardian</small></p></body></html>"
    )
    return {
        "statusCode": status,
        "headers": {**_HEADERS, **(extra_headers or {})},
        "body": document,
    }


def _message(status: int, title: str, text: str):
    return _page(status, title, f"<p>{html.escape(text)}</p>")


def _describe(approval: Approval, region: str) -> tuple[str, str] | None:
    """(region, volume id) if the executor would accept this approval, else None.

    Uses the executor's own strict parser, so this page can only ever offer an action
    that the executor will really carry out.
    """
    if approval.action not in KNOWN_ACTIONS:
        return None
    try:
        target = ebs_delete.parse_finding_id(approval.finding_id, region)
    except ebs_delete.OutOfScope:
        return None
    return target.region, target.volume_id


def _confirm_page(approval: Approval, token: str, live: bool, region: str):
    described = _describe(approval, region)
    if described is None:
        return _message(
            400,
            "Cannot approve this",
            "This approval is for an action this version of Cloud Guardian does not support.",
        )
    region, volume_id = described
    banner = (
        "<p class=warn>DRY RUN: pressing the button changes nothing. "
        "It only shows what would happen.</p>"
        if not live
        else "<p class=warn>This will delete the volume after a backup snapshot is taken.</p>"
    )
    button = "Show what would happen" if not live else "Back up and delete this volume"
    css_class = " class=safe" if not live else ""
    body = (
        f"<div class=box><p>Volume <b>{html.escape(volume_id)}</b> in "
        f"<b>{html.escape(region)}</b> is not attached to anything.</p>"
        "<p>Cloud Guardian will first take a backup snapshot. It checks again that the "
        "volume is still unattached and not tagged <code>guardian:ignore</code> before "
        "deleting anything.</p></div>"
        f"{banner}"
        "<form method=post action=\"\">"
        f"<input type=hidden name=t value=\"{html.escape(token, quote=True)}\">"
        f"<button type=submit{css_class}>{html.escape(button)}</button></form>"
        "<p><small>If you did not expect this, just close the page. Nothing happens until "
        "you press the button, and the link expires on its own.</small></p>"
    )
    return _page(200, "Confirm clean-up", body)


def _method(event: dict[str, Any]) -> str:
    return str(event.get("requestContext", {}).get("http", {}).get("method", "")).upper()


def _read_body(event: dict[str, Any]) -> str | None:
    """The request body as text, or None if it is too big or unreadable."""
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(body, validate=True)
        except ValueError:
            return None
    else:
        raw = body.encode()
    if len(raw) > MAX_BODY_BYTES:
        return None
    return raw.decode("utf-8", "replace")


def handle(
    event: dict[str, Any],
    *,
    store: ApprovalStore,
    invoke: Invoker,
    live: bool,
    region: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    method = _method(event)

    if method == "GET":
        token = ((event.get("queryStringParameters") or {}).get("t")) or ""
        try:
            approval = store.peek(token, now)
        except ApprovalError as exc:
            return _message(400, "Approval link problem", exc.reason)
        return _confirm_page(approval, token, live, region)

    if method == "POST":
        body = _read_body(event)
        if body is None:
            return _message(413, "Request refused", "That request was not accepted.")
        token = (parse_qs(body).get("t") or [""])[0]
        try:
            approval = store.peek(token, now)
        except ApprovalError as exc:
            return _message(400, "Approval link problem", exc.reason)
        if _describe(approval, region) is None:
            return _message(400, "Cannot approve this", "This approval is not supported.")
        return _act(approval, token, store=store, invoke=invoke, live=live, now=now)

    return _page(
        405, "Not allowed", "<p>Use the link from your email.</p>", {"Allow": "GET, POST"}
    )


def _act(
    approval: Approval,
    token: str,
    *,
    store: ApprovalStore,
    invoke: Invoker,
    live: bool,
    now: datetime | None,
):
    if not live:
        # Dry run: the approval is NOT used up, so the same link can be used again.
        try:
            result = invoke(approval.approval_id, True) or {}
        except Exception:  # noqa: BLE001
            logger.exception("Dry run could not be started")
            return _message(500, "Dry run failed", "The dry run could not be completed.")
        return _page(
            200,
            "Dry run result",
            f"<div class=box><p>{html.escape(str(result.get('detail', 'no detail')))}</p></div>"
            "<p>Nothing was changed, and the link still works.</p>",
        )

    # Live: claim first (exactly once), then hand over.
    try:
        claimed = store.claim(token, now)
    except ApprovalError as exc:
        return _message(400, "Approval link problem", exc.reason)

    try:
        invoke(claimed.approval_id, False)
    except Exception:  # noqa: BLE001
        logger.exception("Could not start the clean-up")
        store.finish(claimed, ebs_delete.STATUS_FAILED, "could not start the clean-up", now)
        return _message(
            500,
            "Could not start",
            "The approval was used but the clean-up could not be started. "
            "Nothing was deleted. Wait for the next report to get a fresh link.",
        )
    return _message(
        200,
        "Approved",
        "Cloud Guardian is backing up and then deleting the volume. "
        "You will get an email with the outcome.",
    )


def make_invoker(lambda_client: Any, function_name: str) -> Invoker:
    """Build the function that starts the executor Lambda."""

    def invoke(approval_id: str, wait: bool) -> dict[str, Any] | None:
        payload = json.dumps({"approval_id": approval_id}).encode()
        if wait:
            response = lambda_client.invoke(
                FunctionName=function_name, InvocationType="RequestResponse", Payload=payload
            )
            if response.get("FunctionError"):
                raise RuntimeError("the executor reported an error")
            return json.loads(response["Payload"].read())
        response = lambda_client.invoke(
            FunctionName=function_name, InvocationType="Event", Payload=payload
        )
        if response.get("StatusCode") != 202:
            raise RuntimeError("the executor was not started")
        return None

    return invoke


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        region = os.environ.get("AWS_REGION", "ap-south-1")
        store = ApprovalStore(
            boto3.resource("dynamodb", region_name=region).Table(os.environ["APPROVALS_TABLE"])
        )
        invoke = make_invoker(
            boto3.client("lambda", region_name=region), os.environ["EXECUTOR_FUNCTION"]
        )
        live = os.environ.get("CLEANUP_MODE") == "live"
        return handle(event, store=store, invoke=invoke, live=live, region=region)
    except Exception:  # noqa: BLE001 - never show internals to the public internet
        logger.exception("Approver failed")
        return _message(500, "Something went wrong", "Please try again later.")
