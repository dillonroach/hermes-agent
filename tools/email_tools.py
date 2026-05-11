"""Email tools — read inbox + send mail through the hermes-msb broker.

Three tools:
  - email_list  — list recent messages in a folder (default INBOX)
  - email_read  — fetch full body of one message by uid
  - email_send  — send a message via SMTP

Credentials live in HERMES_HOME/.env and are read by the broker; the agent
never sees them. See README's "Email" section for setup.

The check_fn returns False when the broker isn't running OR when neither
EMAIL_IMAP_HOST nor EMAIL_SMTP_HOST is configured — Hermes won't expose the
tools to the model in either case.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from tools.registry import registry, tool_error


def _broker_endpoint() -> tuple[str, str] | None:
    port = os.environ.get("HERMES_MSB_BROKER_PORT")
    token_file = os.environ.get("HERMES_MSB_BROKER_TOKEN_FILE")
    if not port or not token_file:
        return None
    try:
        token = Path(token_file).read_text().strip()
    except OSError:
        return None
    if not token:
        return None
    return f"http://127.0.0.1:{port}", token


def _imap_configured() -> bool:
    return bool(os.environ.get("EMAIL_IMAP_HOST")
                and os.environ.get("EMAIL_IMAP_USER")
                and os.environ.get("EMAIL_IMAP_PASSWORD"))


def _smtp_configured() -> bool:
    if not os.environ.get("EMAIL_SMTP_HOST"):
        return False
    user = os.environ.get("EMAIL_SMTP_USER") or os.environ.get("EMAIL_IMAP_USER")
    pwd = os.environ.get("EMAIL_SMTP_PASSWORD") or os.environ.get("EMAIL_IMAP_PASSWORD")
    return bool(user and pwd)


def _check_imap() -> bool:
    return _broker_endpoint() is not None and _imap_configured()


def _check_smtp() -> bool:
    return _broker_endpoint() is not None and _smtp_configured()


def _broker_post(path: str, payload: dict, timeout: float = 60.0) -> str:
    endpoint = _broker_endpoint()
    if endpoint is None:
        return tool_error("hermes-msb broker not running")
    base_url, token = endpoint
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail")
        except Exception:
            detail = exc.reason
        return tool_error(f"broker returned {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        return tool_error(f"could not reach broker: {exc.reason}")
    except Exception as exc:
        return tool_error(f"unexpected error: {exc}")


# ---------------------------------------------------------------------------
# email_list
# ---------------------------------------------------------------------------


EMAIL_LIST_SCHEMA = {
    "name": "email_list",
    "description": (
        "List recent messages in an IMAP folder (default INBOX) via the broker. "
        "Returns metadata only (uid, from, subject, date, message_id) — no "
        "bodies. Use `email_read` to fetch a specific message's content. "
        "Newest-first; capped to `limit` (default 25, max 200)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "folder": {"type": "string", "default": "INBOX"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25},
            "unread_only": {"type": "boolean", "default": False},
        },
    },
}


def email_list_tool(folder: str = "INBOX", limit: int = 25, unread_only: bool = False) -> str:
    return _broker_post("/email/list", {
        "folder": folder, "limit": limit, "unread_only": unread_only,
    })


registry.register(
    name="email_list",
    toolset="email",
    schema=EMAIL_LIST_SCHEMA,
    handler=lambda args, **kw: email_list_tool(
        folder=args.get("folder", "INBOX"),
        limit=int(args.get("limit", 25)),
        unread_only=bool(args.get("unread_only", False)),
    ),
    check_fn=_check_imap,
    emoji="📬",
)


# ---------------------------------------------------------------------------
# email_read
# ---------------------------------------------------------------------------


EMAIL_READ_SCHEMA = {
    "name": "email_read",
    "description": (
        "Fetch the full body of a single email by its IMAP uid (returned from "
        "`email_list`). Returns from/to/cc/subject/date/body_text/body_html "
        "and a list of attachment filenames (no attachment content)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "IMAP uid from email_list."},
            "folder": {"type": "string", "default": "INBOX"},
        },
        "required": ["uid"],
    },
}


def email_read_tool(uid: str, folder: str = "INBOX") -> str:
    if not uid or not str(uid).strip():
        return tool_error("uid is required")
    return _broker_post("/email/read", {"uid": str(uid).strip(), "folder": folder})


registry.register(
    name="email_read",
    toolset="email",
    schema=EMAIL_READ_SCHEMA,
    handler=lambda args, **kw: email_read_tool(
        uid=args.get("uid", ""),
        folder=args.get("folder", "INBOX"),
    ),
    check_fn=_check_imap,
    emoji="📖",
)


# ---------------------------------------------------------------------------
# email_send
# ---------------------------------------------------------------------------


EMAIL_SEND_SCHEMA = {
    "name": "email_send",
    "description": (
        "Send an email via SMTP through the broker. From-address is set on the "
        "host (EMAIL_FROM env var, defaulting to EMAIL_SMTP_USER) — the agent "
        "cannot spoof. The broker audit-logs every send."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ],
                "description": "Recipient(s); string with comma-separated addresses, or list of strings.",
            },
            "subject": {"type": "string"},
            "body_text": {"type": "string", "description": "Plain-text body."},
            "body_html": {"type": "string", "description": "Optional HTML body alternative."},
            "cc": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ],
            },
            "bcc": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ],
            },
        },
        "required": ["to", "subject"],
    },
}


def email_send_tool(
    to: Any,
    subject: str,
    body_text: str = "",
    body_html: str | None = None,
    cc: Any = None,
    bcc: Any = None,
) -> str:
    payload: dict[str, Any] = {"to": to, "subject": subject, "body_text": body_text}
    if body_html:
        payload["body_html"] = body_html
    if cc:
        payload["cc"] = cc
    if bcc:
        payload["bcc"] = bcc
    return _broker_post("/email/send", payload)


registry.register(
    name="email_send",
    toolset="email",
    schema=EMAIL_SEND_SCHEMA,
    handler=lambda args, **kw: email_send_tool(
        to=args.get("to"),
        subject=args.get("subject", ""),
        body_text=args.get("body_text", "") or args.get("body", ""),
        body_html=args.get("body_html"),
        cc=args.get("cc"),
        bcc=args.get("bcc"),
    ),
    check_fn=_check_smtp,
    emoji="📤",
)
