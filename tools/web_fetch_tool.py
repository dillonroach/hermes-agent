"""web_fetch tool — outbound HTTP through the hermes-msb broker.

Routes the agent's web requests through the host-side broker, which enforces:
  - URL deny-globs (paste sites, webhook receivers, etc.)
  - SSRF protection (refuses private / loopback / metadata IPs)
  - Per-call audit logging

With this tool active, the VM's network policy can be locked down to
`host`-only — the agent loses direct outbound HTTP, has to go through the
broker, every fetch becomes auditable. See the README's "Adjust the
network policy" section.

Availability is gated on `HERMES_MSB_BROKER_PORT` / `HERMES_MSB_BROKER_TOKEN_FILE`
in the host process's env. The check_fn returns False otherwise — Hermes won't
expose this tool to the model when the broker isn't running.
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


def _check() -> bool:
    return _broker_endpoint() is not None


WEB_FETCH_SCHEMA = {
    "name": "web_fetch",
    "description": (
        "Fetch a URL via the host-side broker. The broker enforces an "
        "exfiltration deny-list (paste sites, webhook receivers, etc.) and "
        "blocks SSRF attempts (private / loopback / metadata IPs). Use this "
        "for any HTTP(S) request the agent needs to make — the VM's network "
        "layer is locked down so direct curl/requests/httpx calls from inside "
        "the sandbox will fail. The broker returns the full response (status, "
        "headers, body) and audit-logs every call."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Absolute http(s) URL.",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"],
                "default": "GET",
            },
            "headers": {
                "type": "object",
                "description": "Optional request headers as a key/value map.",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "string",
                "description": "Optional request body (POST/PUT/PATCH).",
            },
            "max_bytes": {
                "type": "integer",
                "minimum": 1,
                "default": 1_000_000,
                "description": "Cap on response body size; the broker truncates past this.",
            },
            "timeout": {
                "type": "number",
                "minimum": 1,
                "default": 30,
                "description": "Per-request timeout in seconds.",
            },
            "allow_redirects": {
                "type": "boolean",
                "default": True,
            },
        },
        "required": ["url"],
    },
}


def web_fetch_tool(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    max_bytes: int = 1_000_000,
    timeout: float = 30.0,
    allow_redirects: bool = True,
) -> str:
    if not url or not url.strip():
        return tool_error("url is required")

    endpoint = _broker_endpoint()
    if endpoint is None:
        return tool_error(
            "web_fetch requires the hermes-msb broker. Launch via scripts/launch.sh."
        )
    base_url, token = endpoint

    payload: dict[str, Any] = {
        "url": url,
        "method": method,
        "max_bytes": max_bytes,
        "timeout": timeout,
        "allow_redirects": allow_redirects,
    }
    if headers:
        payload["headers"] = headers
    if body is not None:
        payload["body"] = body

    req = urllib.request.Request(
        f"{base_url}/web/fetch",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        # Use a slightly-longer-than-broker timeout so the broker's own timeout
        # is what surfaces in errors (rather than a transport-layer cut here).
        with urllib.request.urlopen(req, timeout=timeout + 10) as r:
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


registry.register(
    name="web_fetch",
    toolset="web",
    schema=WEB_FETCH_SCHEMA,
    handler=lambda args, **kw: web_fetch_tool(
        url=args.get("url", ""),
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        body=args.get("body"),
        max_bytes=args.get("max_bytes", 1_000_000),
        timeout=args.get("timeout", 30.0),
        allow_redirects=args.get("allow_redirects", True),
    ),
    check_fn=_check,
    emoji="🌐",
)
