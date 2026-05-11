"""microsandbox execution environment — microVM-based sandboxing for Hermes.

Provides libkrun-backed microVM isolation for the agent's terminal,
code-execution, and file tools:
- Spawn-per-call via _ThreadedProcessHandle wrapping async microsandbox SDK calls.
- One long-lived sandbox per session; bind-mounts a host workspace to /workspace.
- cancel_fn wired to ExecHandle.kill() so interrupts terminate the running command,
  not the whole VM.
- Optional integration with a host-side broker (hermes-msb) for audited host-fs,
  web-fetch, and email access; auto-detected via env vars at session start.
- Network policy is configurable per session (defaults to microsandbox's
  public_only); a deny-by-default policy is recommended when the broker is on,
  so the agent's outbound HTTP flows through `web_fetch` rather than direct.
"""

import asyncio
import json
import logging
import os
import shlex
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from tools.environments.base import (
    BaseEnvironment,
    _ThreadedProcessHandle,
    get_sandbox_dir,
)

logger = logging.getLogger(__name__)


class _AsyncWorker:
    """Background thread with a dedicated event loop for async microsandbox calls.

    Mirrors tools/environments/modal.py: the BaseEnvironment expects synchronous
    `_run_bash() -> ProcessHandle`, but the microsandbox SDK is async-only.
    We run an event loop in a daemon thread and submit coroutines to it via
    `run_coroutine_threadsafe`.
    """

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._started.wait(timeout=30)
        if self._loop is None:
            raise RuntimeError("microsandbox AsyncWorker failed to start its event loop")

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._started.set()
        self._loop.run_forever()

    def run_coroutine(self, coro, timeout: float = 600) -> Any:
        if self._loop is None or self._loop.is_closed():
            raise RuntimeError("AsyncWorker loop is not running")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def stop(self) -> None:
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=10)


def _translate_volumes(
    volumes: list | None,
    host_workspace: Optional[str],
    auto_mount_workspace: bool,
) -> dict:
    """Translate Hermes-style 'host:guest[:ro]' volume strings to microsandbox spec dict.

    NOTE: the `:ro` flag on directory bind mounts is parsed by microsandbox
    but NOT actually enforced at the FS layer. We pass the flag through (and
    microsandbox's API accepts it), but callers MUST NOT assume a `:ro`
    directory mount is read-only. For genuine read-only host browsing, route
    through the broker's host_fs tools rather than relying on the mount flag.
    """
    from microsandbox import Volume

    result: dict[str, Any] = {}
    workspace_explicitly_mounted = False

    for entry in (volumes or []):
        if not isinstance(entry, str):
            logger.warning("microsandbox volume entry is not a string: %r", entry)
            continue
        spec = entry.strip()
        if not spec:
            continue
        parts = spec.split(":")
        if len(parts) < 2:
            logger.warning("microsandbox volume '%s' missing colon, skipping", spec)
            continue
        host_path, guest_path = parts[0], parts[1]
        readonly = len(parts) >= 3 and parts[2] == "ro"
        result[guest_path] = Volume.bind(host_path, readonly=readonly)
        if guest_path == "/workspace":
            workspace_explicitly_mounted = True

    if auto_mount_workspace and host_workspace and not workspace_explicitly_mounted:
        host_workspace_abs = os.path.abspath(os.path.expanduser(host_workspace))
        if os.path.isdir(host_workspace_abs):
            result["/workspace"] = Volume.bind(host_workspace_abs, readonly=False)
        else:
            logger.warning(
                "microsandbox auto_mount_workspace requested but host path does not exist: %s",
                host_workspace_abs,
            )

    return result


def _run_dir() -> Path:
    """Return the directory used to record running-sandbox PID files for the janitor.

    Lives under the same sandbox-dir tree as workspaces, so it travels with
    HERMES_HOME and is auto-created by ``get_sandbox_dir``.
    """
    p = get_sandbox_dir() / "microsandbox" / "run"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _build_network(network_config: dict | None):
    """Build a microsandbox Network from a Hermes config block.

    Supported shapes:

    1. Convenience preset:
        {policy: "public_only" | "allow_all" | "none"}

    2. Custom default-deny + rules:
        {default_egress: "deny" | "allow",
         rules: [
             {action: "allow"|"deny",
              direction: "egress"|"ingress",   # default: egress
              destination: "<group> | <suffix> | <CIDR>",
              protocol: "tcp"|"udp",            # optional
              port: <int|str>},                  # optional
             ...
         ]}

    Destination groups recognized by microsandbox: ``*, public, loopback,
    private, link-local, metadata, multicast, host``. Anything else is
    treated as a domain (suffix match) or CIDR. Spike 0c confirmed suffix
    matching against domains like ``anthropic.com``.
    """
    from microsandbox import Action, Direction, Network, NetworkPolicy, Rule

    if not network_config:
        return None

    policy_name = network_config.get("policy")

    # Convenience presets
    if policy_name == "public_only":
        return Network.public_only()
    if policy_name == "allow_all":
        return Network.allow_all()
    if policy_name == "none":
        return Network.none()

    # Custom policy: build from default_egress + rules
    if policy_name in (None, "custom"):
        rules_in = network_config.get("rules") or []
        if not rules_in and "default_egress" not in network_config:
            return None  # nothing specified — fall back to SDK default

        default_egress_str = str(network_config.get("default_egress", "deny")).lower()
        default_egress = Action.DENY if default_egress_str == "deny" else Action.ALLOW

        rule_objs: list[Rule] = []
        for raw in rules_in:
            if not isinstance(raw, dict):
                logger.warning("microsandbox network rule is not a mapping: %r", raw)
                continue
            action_str = str(raw.get("action") or "allow").lower()
            action = Action.ALLOW if action_str == "allow" else Action.DENY

            direction_str = str(raw.get("direction") or "egress").lower()
            direction = Direction.EGRESS if direction_str == "egress" else Direction.INGRESS

            rule_objs.append(Rule(
                action=action,
                direction=direction,
                destination=raw.get("destination"),
                protocol=None,  # passthrough not yet supported in this config schema
                port=raw.get("port"),
            ))

        return Network(policy=NetworkPolicy(
            default_egress=default_egress,
            rules=tuple(rule_objs),
        ))

    logger.warning(
        "microsandbox network.policy=%r not recognized; using SDK default", policy_name
    )
    return None


class MicrosandboxEnvironment(BaseEnvironment):
    """microsandbox-backed execution environment.

    Boots one microVM per session, with the host workspace bind-mounted to
    /workspace. Each `_run_bash` call runs a fresh `bash -c` inside the VM
    via the microsandbox SDK's `exec_stream`.
    """

    # SDK exec doesn't expose a writable stdin from synchronous callers, so the
    # base class embeds stdin as a heredoc before calling _run_bash.
    _stdin_mode = "heredoc"

    # microsandbox warm boot is sub-second per spike 0a; a generous snapshot
    # budget covers cold-pull cases.
    _snapshot_timeout = 60

    def __init__(
        self,
        image: str,
        cwd: str = "/workspace",
        timeout: int = 60,
        cpus: int = 2,
        memory_mib: int = 4096,
        task_id: str = "default",
        volumes: list | None = None,
        host_cwd: str | None = None,
        auto_mount_cwd: bool = True,
        env: dict | None = None,
        network: dict | None = None,
        sandbox_name: str | None = None,
    ) -> None:
        if cwd in ("~", "~/"):
            cwd = "/workspace"
        super().__init__(cwd=cwd, timeout=timeout, env=env or {})

        self._image = image
        self._cpus = max(1, int(cpus))
        self._memory_mib = max(256, int(memory_mib))
        self._task_id = task_id
        self._network_cfg = network
        self._sandbox = None
        self._sandbox_name = sandbox_name or f"hermes-{uuid.uuid4().hex[:12]}"
        self._worker = _AsyncWorker()

        # Resolve workspace host path. If the caller didn't pass one, default
        # to a per-task dir under the sandbox root so this still produces a
        # working backend even without explicit config.
        if host_cwd:
            workspace_host = host_cwd
        else:
            workspace_host = str(get_sandbox_dir() / "microsandbox" / task_id / "workspace")
        # Always mkdir defensively — without this, a missing dir silently
        # disables the bind, which then makes /workspace not exist in the VM,
        # which then makes our login-shell `cd /workspace` fail silently
        # (`|| true`) and self.cwd gets clobbered to `/`.
        try:
            os.makedirs(workspace_host, exist_ok=True)
        except OSError as exc:
            logger.warning("microsandbox: could not mkdir workspace host path %s: %s",
                           workspace_host, exc)
        self._workspace_host = workspace_host

        # Translate volumes config to microsandbox spec dict.
        volumes_kwarg = _translate_volumes(
            volumes=volumes,
            host_workspace=workspace_host,
            auto_mount_workspace=auto_mount_cwd,
        )

        # Mount Hermes's skills tree into the VM at /root/.hermes/skills/ so
        # skill scripts/templates/references are reachable from inside the
        # sandbox. Same convention the Docker backend uses (via
        # get_skills_directory_mount). Without this, skills that ship a
        # `scripts/foo.py` would have nothing for the agent to actually run.
        # Caller-supplied volumes win — we only fill in what's missing.
        try:
            from microsandbox import Volume as _Volume
            from tools.credential_files import (
                get_skills_directory_mount,
                get_credential_file_mounts,
            )
            for mount_entry in get_skills_directory_mount():
                guest = mount_entry["container_path"]
                if guest in volumes_kwarg:
                    continue
                volumes_kwarg[guest] = _Volume.bind(
                    mount_entry["host_path"], readonly=False
                )
            # Also mount credential files (OAuth tokens, etc.) declared by
            # skills.  Read-only so the VM can authenticate but not edit them.
            for mount_entry in get_credential_file_mounts():
                guest = mount_entry["container_path"]
                if guest in volumes_kwarg:
                    continue
                volumes_kwarg[guest] = _Volume.bind(
                    mount_entry["host_path"], readonly=True
                )
        except Exception as exc:
            logger.warning(
                "microsandbox: could not resolve skills/credential mounts: %s", exc
            )
        if "/workspace" in volumes_kwarg:
            logger.info("microsandbox: /workspace bound from host=%s (RW)", workspace_host)
        else:
            logger.warning(
                "microsandbox: /workspace NOT bound — agent will start at VM root, not in a host-visible workspace. "
                "auto_mount_cwd=%s, host_cwd=%s, workspace_host=%s, host_dir_exists=%s",
                auto_mount_cwd, host_cwd, workspace_host, os.path.isdir(workspace_host),
            )

        # Validate microsandbox import early so the user gets a clear error
        # if they selected this backend without installing the SDK.
        try:
            import microsandbox  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "microsandbox backend selected but the 'microsandbox' Python SDK is "
                "not installed. Install it with: pip install 'hermes-agent[microsandbox]'"
            ) from exc

        # Boot the AsyncWorker, then create the sandbox via the SDK.
        self._worker.start()
        self._create_sandbox(volumes_kwarg)

        # If the host-side broker is running, discover the per-VM default
        # gateway IP and write BROKER_URL/BROKER_TOKEN into the VM via
        # /etc/profile.d/hermes-broker.sh. init_session() (called below with
        # bash -l) sources profile.d, captures the env into the snapshot, and
        # every subsequent command's wrapper re-sources the snapshot — so the
        # values persist across stateless exec_stream calls.
        self._gateway_ip: str | None = None
        broker_port = os.getenv("HERMES_MSB_BROKER_PORT")
        broker_token_file = os.getenv("HERMES_MSB_BROKER_TOKEN_FILE")
        if broker_port and broker_token_file:
            self._inject_broker_env(broker_port, broker_token_file)

        # Record this sandbox's existence so a reaper can clean it up if
        # Hermes is hard-killed (microsandbox has no PR_SET_PDEATHSIG hook,
        # so orphan VMs would otherwise linger).
        self._pid_file = _run_dir() / f"{self._sandbox_name}.pid"
        self._write_pid_file()

        # Initialize session snapshot inside the VM.
        self.init_session()

    # ------------------------------------------------------------------
    # Sandbox lifecycle
    # ------------------------------------------------------------------

    def _create_sandbox(self, volumes_kwarg: dict) -> None:
        """Boot the microVM via Sandbox.create(). Blocking via the worker thread."""
        from microsandbox import Sandbox

        kwargs: dict[str, Any] = {
            "image": self._image,
            "cpus": self._cpus,
            "memory": self._memory_mib,
            "replace": True,  # idempotent re-runs on the same name
        }
        if volumes_kwarg:
            kwargs["volumes"] = volumes_kwarg
        if self.env:
            kwargs["env"] = dict(self.env)
        net = _build_network(self._network_cfg)
        if net is not None:
            kwargs["network"] = net

        async def _create() -> Any:
            return await Sandbox.create(self._sandbox_name, **kwargs)

        try:
            self._sandbox = self._worker.run_coroutine(_create(), timeout=180)
            logger.info(
                "microsandbox: created sandbox %s (image=%s, cpus=%d, memory=%dMiB, workspace=%s)",
                self._sandbox_name, self._image, self._cpus, self._memory_mib, self._workspace_host,
            )
        except Exception:
            # Tear down the worker so we don't leak the event-loop thread.
            self._worker.stop()
            raise

    # ------------------------------------------------------------------
    # Broker env injection
    # ------------------------------------------------------------------

    def _inject_broker_env(self, port: str, token_file: str) -> None:
        """Discover the VM's default-gateway IP and write BROKER_URL/TOKEN
        into /etc/profile.d/hermes-broker.sh inside the VM.

        Must run before init_session(), so the bash -l snapshot captures the
        new env vars. Subsequent stateless `bash -c` calls re-source the
        snapshot and inherit them.
        """
        sandbox = self._sandbox
        if sandbox is None:
            return

        # Two-tier gateway discovery so we work across images:
        #   1. `ip route show default` — present on alpine and most images that ship iproute2.
        #   2. python3 parsing /proc/net/route — works on python:3.12-slim where
        #      iproute2 isn't installed by default but the image-name guarantees python3.
        # Fails closed: if neither path produces a gateway, broker injection skips.
        gateway_script = r"""
gw=""
if command -v ip >/dev/null 2>&1; then
    gw=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
fi
if [ -z "$gw" ] && command -v python3 >/dev/null 2>&1; then
    gw=$(python3 - <<'PYEOF'
import socket, struct
with open("/proc/net/route") as f:
    next(f)
    for line in f:
        p = line.split()
        if p[1] == "00000000":
            print(socket.inet_ntoa(struct.pack("<L", int(p[2], 16))))
            break
PYEOF
)
fi
printf '%s' "$gw"
"""

        async def _do() -> str:
            out = await sandbox.shell(gateway_script)
            gateway_ip = (out.stdout_text or "").strip().splitlines()
            gateway_ip = gateway_ip[0].strip() if gateway_ip else ""
            if not gateway_ip:
                raise RuntimeError("could not determine VM default gateway")

            try:
                token = Path(token_file).read_text().strip()
            except OSError as exc:
                raise RuntimeError(f"could not read broker token: {exc}")

            broker_url = f"http://{gateway_ip}:{port}"
            script = (
                "# Auto-generated by hermes-msb backend.\n"
                "# Sourced by login shells; provides broker URL/token to the agent.\n"
                f"export BROKER_URL='{broker_url}'\n"
                f"export BROKER_TOKEN='{token}'\n"
            )
            # Ensure the dir exists (it does on debian-based images, but be defensive).
            await sandbox.shell("mkdir -p /etc/profile.d")
            await sandbox.fs.write("/etc/profile.d/hermes-broker.sh", script.encode("utf-8"))
            await sandbox.shell("chmod 0644 /etc/profile.d/hermes-broker.sh")
            return gateway_ip

        try:
            self._gateway_ip = self._worker.run_coroutine(_do(), timeout=15)
            logger.info(
                "microsandbox: broker env injected (gateway=%s, port=%s)",
                self._gateway_ip, port,
            )
        except Exception as exc:
            logger.warning("microsandbox: broker env injection failed: %s", exc)

    # ------------------------------------------------------------------
    # PID-file bookkeeping (consumed by the orphan-VM janitor)
    # ------------------------------------------------------------------

    def _write_pid_file(self) -> None:
        """Record this sandbox so a reaper can clean it up after a hard kill."""
        try:
            payload = {
                "hermes_pid": os.getpid(),
                "sandbox_name": self._sandbox_name,
                "image": self._image,
                "task_id": self._task_id,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            self._pid_file.write_text(json.dumps(payload, indent=2))
        except Exception as exc:
            logger.warning("microsandbox: could not write PID file %s: %s", self._pid_file, exc)

    def _remove_pid_file(self) -> None:
        try:
            if self._pid_file.exists():
                self._pid_file.unlink()
        except Exception as exc:
            logger.debug("microsandbox: could not remove PID file %s: %s", self._pid_file, exc)

    # ------------------------------------------------------------------
    # Required BaseEnvironment overrides
    # ------------------------------------------------------------------

    def _run_bash(
        self,
        cmd_string: str,
        *,
        login: bool = False,
        timeout: int = 120,
        stdin_data: str | None = None,
    ):
        """Run cmd_string in the sandbox; return a ProcessHandle for the base
        class's _wait_for_process to drain.

        With `_stdin_mode = "heredoc"`, the base class has already embedded any
        stdin data into cmd_string, so stdin_data should be None here. We
        ignore it defensively.
        """
        assert self._sandbox is not None, "microsandbox sandbox not started"
        sandbox = self._sandbox
        worker = self._worker

        # microsandbox VMs default `pwd` to `/` on every fresh exec (no `-w`
        # equivalent in Sandbox.create). BaseEnvironment.init_session()'s
        # bootstrap captures the snapshot WITHOUT cd'ing first, so without
        # this prefix self.cwd would get clobbered to "/" the moment
        # init_session runs. Login-shell calls = init_session + fallback when
        # snapshotting fails; both want to start in our configured cwd.
        # Non-login calls go through _wrap_command, which already injects
        # `builtin cd <cwd>`, so we leave them alone.
        if login and self.cwd and self.cwd != "/":
            cmd_string = (
                f"cd {shlex.quote(self.cwd)} 2>/dev/null || true\n{cmd_string}"
            )

        # Box for the ExecHandle so cancel_fn can find it after _do() starts.
        handle_box: list = []

        def cancel() -> None:
            if not handle_box:
                return
            try:
                # Wrap the SDK call in an async closure so the awaitable is
                # constructed on the worker loop, not the calling thread —
                # microsandbox's pyo3-asyncio bindings require a running loop
                # in the thread that creates the future.
                async def _kill():
                    await handle_box[0].kill()
                worker.run_coroutine(_kill(), timeout=5)
            except Exception:
                pass

        def exec_fn() -> tuple[str, int]:
            async def _do() -> tuple[str, int]:
                bash_args = ["-l", "-c", cmd_string] if login else ["-c", cmd_string]
                handle = await sandbox.exec_stream("bash", bash_args)
                handle_box.append(handle)
                output = await handle.collect()
                stdout = output.stdout_text
                stderr = output.stderr_text
                if stderr:
                    text = f"{stdout}\n{stderr}" if stdout else stderr
                else:
                    text = stdout
                return text, output.exit_code

            return worker.run_coroutine(_do(), timeout=timeout + 30)

        return _ThreadedProcessHandle(exec_fn, cancel_fn=cancel)

    def cleanup(self) -> None:
        """Stop the VM and tear down the worker thread. Idempotent.

        All SDK calls are wrapped in async closures so the awaitables get
        constructed on the worker loop, not the calling thread — pyo3-asyncio
        futures pin to the loop running when they're created.
        """
        if self._sandbox is None:
            return
        sandbox = self._sandbox
        sandbox_name = self._sandbox_name
        try:
            try:
                async def _stop():
                    return await sandbox.stop_and_wait()
                self._worker.run_coroutine(_stop(), timeout=15)
            except Exception as exc:
                logger.warning("microsandbox: stop_and_wait failed: %s", exc)
                try:
                    async def _kill():
                        await sandbox.kill()
                    self._worker.run_coroutine(_kill(), timeout=10)
                except Exception:
                    pass
            try:
                from microsandbox import Sandbox

                async def _remove():
                    await Sandbox.remove(sandbox_name)
                self._worker.run_coroutine(_remove(), timeout=10)
            except Exception:
                pass
        finally:
            self._remove_pid_file()
            self._worker.stop()
            self._sandbox = None
