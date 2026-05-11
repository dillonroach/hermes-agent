"""Host-side file-access tools that route through the hermes-msb broker.

These tools are the agent's only mechanism for reading host files outside
`/workspace`. The broker enforces an allow-list of permitted paths and a
deny-list of sensitive globs.

Three tools:
  - host_fs_read  — read a host file (bytes, may be sliced via offset/limit)
  - host_fs_list  — list a host directory's entries
  - host_fs_stat  — get a host path's metadata

Availability is gated on `HERMES_MSB_BROKER_PORT` / `HERMES_MSB_BROKER_TOKEN_FILE`
being present in the host process's environment, which `scripts/launch.sh`
sets up. The check_fn returns False otherwise — Hermes won't expose the tools
to the model when the broker isn't running.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from tools.registry import registry, tool_error


def _broker_endpoint() -> tuple[str, str] | None:
    """Resolve (base_url, token) for the host-side broker, or None if unavailable.

    Host-side tools call the broker on 127.0.0.1 (NOT the per-VM gateway IP —
    that's only used from inside the VM).
    """
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


def _broker_get(path: str, params: dict) -> tuple[int, bytes, str | None]:
    """Issue an authenticated GET to the broker. Returns (status, body, content_type)."""
    endpoint = _broker_endpoint()
    if endpoint is None:
        raise RuntimeError("hermes-msb broker not configured (HERMES_MSB_BROKER_PORT unset)")
    base_url, token = endpoint
    qs = urllib.parse.urlencode(params)
    url = f"{base_url}{path}?{qs}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        return e.code, e.read() if hasattr(e, "read") else b"", None


def _broker_error_detail(body: bytes) -> str:
    try:
        return json.loads(body.decode("utf-8")).get("detail") or ""
    except Exception:
        return body.decode("utf-8", errors="replace")[:200]


def _check() -> bool:
    return _broker_endpoint() is not None


# ---------------------------------------------------------------------------
# host_fs_read
# ---------------------------------------------------------------------------


HOST_FS_READ_SCHEMA = {
    "name": "host_fs_read",
    "description": (
        "Read a file from the HOST filesystem (outside /workspace) via the "
        "host-side broker. The broker enforces an allow-list of permitted "
        "paths plus a deny-list of sensitive globs (.env, .ssh/**, etc.). "
        "Use this when the user points you at a file in ~/Documents or "
        "~/Projects and you need to inspect it. For files inside /workspace, "
        "use the regular `read_file` tool — it's faster (no broker round-trip)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absolute host path or ~/path. Must be inside the broker's allow-list.",
            },
            "offset": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1, "default": 1_000_000},
        },
        "required": ["path"],
    },
}


def host_fs_read_tool(path: str, offset: int = 0, limit: int = 1_000_000) -> str:
    if not path or not path.strip():
        return tool_error("path is required")
    try:
        status, body, _ctype = _broker_get(
            "/host_fs/read", {"path": path, "offset": offset, "limit": limit}
        )
    except Exception as exc:
        return tool_error(f"could not reach broker: {exc}")
    if status == 200:
        try:
            text = body.decode("utf-8")
            return json.dumps({"path": path, "encoding": "utf-8", "content": text}, ensure_ascii=False)
        except UnicodeDecodeError:
            return json.dumps({
                "path": path,
                "encoding": "base64",
                "content_b64": base64.b64encode(body).decode("ascii"),
            })
    return tool_error(f"broker returned {status}: {_broker_error_detail(body)}")


registry.register(
    name="host_fs_read",
    toolset="host_fs",
    schema=HOST_FS_READ_SCHEMA,
    handler=lambda args, **kw: host_fs_read_tool(
        path=args.get("path", ""),
        offset=args.get("offset", 0),
        limit=args.get("limit", 1_000_000),
    ),
    check_fn=_check,
    emoji="📁",
)


# ---------------------------------------------------------------------------
# host_fs_list
# ---------------------------------------------------------------------------


HOST_FS_LIST_SCHEMA = {
    "name": "host_fs_list",
    "description": (
        "List the entries of a HOST directory (outside /workspace) via the "
        "host-side broker. Subject to the same allow-list/deny-list as "
        "host_fs_read. Returns name, kind (file/dir/other), size, mtime."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
        },
        "required": ["path"],
    },
}


def host_fs_list_tool(path: str) -> str:
    if not path or not path.strip():
        return tool_error("path is required")
    try:
        status, body, _ = _broker_get("/host_fs/list", {"path": path})
    except Exception as exc:
        return tool_error(f"could not reach broker: {exc}")
    if status == 200:
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return tool_error("broker returned non-utf8 body")
    return tool_error(f"broker returned {status}: {_broker_error_detail(body)}")


registry.register(
    name="host_fs_list",
    toolset="host_fs",
    schema=HOST_FS_LIST_SCHEMA,
    handler=lambda args, **kw: host_fs_list_tool(path=args.get("path", "")),
    check_fn=_check,
    emoji="📂",
)


# ---------------------------------------------------------------------------
# host_fs_stat
# ---------------------------------------------------------------------------


HOST_FS_STAT_SCHEMA = {
    "name": "host_fs_stat",
    "description": (
        "Get metadata (kind, size, mode, mtime, uid/gid) for a HOST path via "
        "the host-side broker. Subject to the same allow-list/deny-list as "
        "host_fs_read."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
        },
        "required": ["path"],
    },
}


def host_fs_stat_tool(path: str) -> str:
    if not path or not path.strip():
        return tool_error("path is required")
    try:
        status, body, _ = _broker_get("/host_fs/stat", {"path": path})
    except Exception as exc:
        return tool_error(f"could not reach broker: {exc}")
    if status == 200:
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return tool_error("broker returned non-utf8 body")
    return tool_error(f"broker returned {status}: {_broker_error_detail(body)}")


registry.register(
    name="host_fs_stat",
    toolset="host_fs",
    schema=HOST_FS_STAT_SCHEMA,
    handler=lambda args, **kw: host_fs_stat_tool(path=args.get("path", "")),
    check_fn=_check,
    emoji="🔎",
)
