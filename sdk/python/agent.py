"""
agentctl Python SDK — stdlib-only, no external deps.

A Python process that uses this module becomes a fully-fledged agent
under `agentctl start --runtime <script>`. It speaks the same framed
VERB/LEN/[REPLY-TO]/[TASK-ID]/payload wire format as the C runtimes
(`reviewer-agent`, `fanout-agent`) and writes the same on-disk task
tree, so `agentctl tasks/task/logs` and `psa` all work unchanged.

The kernel never sees Python; the engine never imports anything.
This is purely a userspace library that lets agent processes be
written in Python instead of C — the architectural boundary
(identity / mailbox / lifecycle in the kernel; everything else in
userspace) is preserved.

Transports:
  - UDS    /tmp/agents/<name>/agent.sock
  - agentfs <mount>/agents/<name>/inbox  (linux-only, kernel module)
Selected per-agent via /tmp/agents/<name>/transport. The same SDK
handles both: only the listener setup branches.
"""

from __future__ import annotations

import errno
import os
import re
import selectors
import signal
import socket
import sys
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional, Tuple

def _resolve_agentctl_root() -> str:
    """Mirror the C resolver in common.c::agentctl_root.

    Precedence:
      1. AGENTCTL_ROOT env (explicit override)
      2. $XDG_RUNTIME_DIR/agentctl
      3. /tmp/agentctl-<uid>
    """
    override = os.environ.get("AGENTCTL_ROOT")
    if override:
        return override
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return os.path.join(xdg, "agentctl")
    return f"/tmp/agentctl-{os.getuid()}"


AGENTCTL_ROOT = _resolve_agentctl_root()
AGENT_ROOT = os.path.join(AGENTCTL_ROOT, "agents")
MAX_PAYLOAD = 1 << 20  # 1 MiB — matches MAX_PAYLOAD in common.h


# ---------------------------------------------------------------------------
# Small file helpers (mirror common.c::atomic_write_file / append_file).
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: str, data, mode: int = 0o600) -> None:
    if isinstance(data, str):
        data = data.encode()
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _append_file(path: str, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Transport resolution + wire format. Mirror common.c::transport_resolve
# and read_message / parse_framed_in_buf.
# ---------------------------------------------------------------------------

def _resolve_transport(agent_dir: str) -> Tuple[str, Optional[str]]:
    line = _read_text(os.path.join(agent_dir, "transport"))
    if not line:
        return ("uds", None)
    line = line.strip()
    if line == "uds":
        return ("uds", None)
    parts = line.split(None, 1)
    if parts and parts[0] == "agentfs" and len(parts) == 2:
        return ("agentfs", parts[1])
    return ("uds", None)


def _build_frame(verb: str, payload: bytes,
                 reply_to: str = "", task_id: str = "") -> bytes:
    lines = [f"VERB {verb}", f"LEN {len(payload)}"]
    if reply_to:
        lines.append(f"REPLY-TO {reply_to}")
    if task_id:
        lines.append(f"TASK-ID {task_id}")
    return ("\n".join(lines) + "\n\n").encode() + payload


def _parse_frame(buf: bytes) -> Tuple[Optional[dict], int]:
    """Parse one full frame from `buf`. Returns (msg, consumed) or (None, 0)."""
    sep = buf.find(b"\n\n")
    if sep < 0:
        return (None, 0)
    header = buf[:sep].decode("utf-8", errors="replace")
    msg = {"verb": None, "payload": b"", "reply_to": "", "task_id": ""}
    plen = -1
    for line in header.split("\n"):
        if not line:
            continue
        if line.startswith("VERB "):
            msg["verb"] = line[5:].lstrip()
        elif line.startswith("LEN "):
            try:
                plen = int(line[4:].strip())
            except ValueError:
                return (None, 0)
        elif line.startswith("REPLY-TO "):
            msg["reply_to"] = line[9:].lstrip()
        elif line.startswith("TASK-ID "):
            msg["task_id"] = line[8:].lstrip()
        # unknown headers ignored (forward-compat, same as the C runtime)
    if plen < 0 or not msg["verb"]:
        return (None, 0)
    start = sep + 2
    if len(buf) - start < plen:
        return (None, 0)
    msg["payload"] = bytes(buf[start:start + plen])
    return (msg, start + plen)


def _recv_one_frame(conn: socket.socket) -> Optional[dict]:
    """Blocking read of one full frame from a connected UDS client."""
    buf = bytearray()
    while True:
        msg, _used = _parse_frame(bytes(buf))
        if msg is not None:
            return msg
        try:
            chunk = conn.recv(65536)
        except InterruptedError:
            continue
        if not chunk:
            return None
        buf.extend(chunk)


# ---------------------------------------------------------------------------
# Caps decorator — APPLICATION-LAYER convenience only.
#
# As of the v1 capability broker, agent authority is fd-based and gated by
# agentd before fds are issued (see broker.h / broker.c). The C reference
# runtimes no longer self-gate against the caps file. This decorator
# remains in the SDK as an opt-in pattern for Python authors who want to
# express handler preconditions in code; it is NOT the canonical security
# boundary.
#
# Behavior: reads /tmp/agents/<name>/caps and applies legacy deny-wins
# matching against `allow`/`deny` lines.
# ---------------------------------------------------------------------------

def _caps_text(agent_dir: str) -> str:
    return _read_text(os.path.join(agent_dir, "policy")) or ""


def _cap_allows(caps_text: str, cap: str) -> bool:
    allow = deny = False
    for raw in caps_text.splitlines():
        line = raw.strip()
        if line.startswith("allow "):
            kw, is_allow = line[6:].strip(), True
        elif line.startswith("deny "):
            kw, is_allow = line[5:].strip(), False
        else:
            continue
        if kw == cap or kw.startswith(cap + ":") or kw.startswith(cap + " "):
            if is_allow:
                allow = True
            else:
                deny = True
    return allow and not deny


class CapabilityError(Exception):
    """Raised by @require_capability when the cap is missing."""


def require_capability(cap: str) -> Callable:
    """Decorator: reject the task unless `caps` grants `cap`."""
    def deco(func: Callable) -> Callable:
        @wraps(func)
        def wrapped(task: "Task", *args, **kwargs):
            if not _cap_allows(_caps_text(task._agent._agent_dir), cap):
                task._agent.log(f"denied verb={task.verb} cap={cap}")
                task.fail(f"missing cap {cap}")
                raise CapabilityError(cap)
            return func(task, *args, **kwargs)
        return wrapped
    return deco


# ---------------------------------------------------------------------------
# Task: one in-flight message + handle to its on-disk row.
# ---------------------------------------------------------------------------

class Task:
    def __init__(self, agent: "Agent", msg: dict):
        self._agent = agent
        self.verb: str = msg["verb"]
        self.payload: bytes = msg["payload"]
        self.sender: str = msg.get("reply_to") or "?"
        self.incoming_task_id: str = msg.get("task_id") or ""
        self.task_id: str = self.incoming_task_id or agent._alloc_task_id()
        self._dir = os.path.join(agent._agent_dir, "tasks", self.task_id)
        self._completed = False
        os.makedirs(os.path.join(self._dir, "artifacts"), exist_ok=True)
        os.makedirs(os.path.join(self._dir, "checkpoints"), exist_ok=True)
        now = _iso_now() + "\n"
        _atomic_write(os.path.join(self._dir, "created_at"), now)
        _atomic_write(os.path.join(self._dir, "updated_at"), now)
        _atomic_write(os.path.join(self._dir, "verb"), self.verb + "\n")
        _atomic_write(os.path.join(self._dir, "sender"), self.sender + "\n")
        _atomic_write(os.path.join(self._dir, "sender_pid"), "0\n")
        _atomic_write(os.path.join(self._dir, "sender_uid"), "0\n")
        if self.sender != "?":
            _atomic_write(os.path.join(self._dir, "reply_to"), self.sender + "\n")
        if self.incoming_task_id:
            _atomic_write(os.path.join(self._dir, "incoming_task_id"),
                          self.incoming_task_id + "\n")
        if self.payload:
            _atomic_write(os.path.join(self._dir, "payload"), self.payload)
        self._set_state("queued")
        self.event(f"created verb={self.verb} sender={self.sender}")

    def _set_state(self, state: str) -> None:
        _atomic_write(os.path.join(self._dir, "state"), state + "\n")
        _atomic_write(os.path.join(self._dir, "status"), state + "\n")
        _atomic_write(os.path.join(self._dir, "updated_at"), _iso_now() + "\n")

    def event(self, line: str) -> None:
        _append_file(os.path.join(self._dir, "events.log"),
                     f"{_iso_now()} {line}\n".encode())

    def write_artifact(self, name: str, content) -> None:
        """Atomic overwrite — matches the worker profile's default policy."""
        path = os.path.join(self._dir, "artifacts", name)
        _atomic_write(path, content)
        n = len(content) if isinstance(content, (bytes, bytearray)) \
            else len(content.encode())
        self._agent.log(f"task={self.task_id} artifact={name} bytes={n}")

    def complete(self, summary: str = "status: completed\n") -> None:
        _atomic_write(os.path.join(self._dir, "result"), summary)
        self._set_state("completed")
        self.event("completed")
        self._completed = True

    def fail(self, reason: str) -> None:
        _atomic_write(os.path.join(self._dir, "result"),
                      f"status: failed\nreason: {reason}\n")
        self._set_state("failed")
        self.event(f"failed: {reason}")
        self._completed = True

    def reply(self, payload=b"", verb: str = "result") -> None:
        if self.sender == "?":
            return
        if isinstance(payload, str):
            payload = payload.encode()
        corr = self.incoming_task_id or self.task_id
        self._agent._send(self.sender, verb,
                          reply_to=self._agent.name,
                          task_id=corr, payload=payload)

    def delegate_to(self, target: str, verb: str, payload=b"") -> None:
        if isinstance(payload, str):
            payload = payload.encode()
        self._agent._send(target, verb,
                          reply_to=self._agent.name,
                          task_id=self.task_id, payload=payload)
        self.event(f"delegated -> {target}")


# ---------------------------------------------------------------------------
# Agent: listener + dispatch loop.
# ---------------------------------------------------------------------------

class Agent:
    def __init__(self, name: Optional[str] = None):
        # spawn_agent_runtime exec's the runtime as:
        #     execl(path, "agent:<name>", name, NULL)
        # with cwd already chdir'd to /tmp/agents/<name>. argv[1] is the name.
        if name is None:
            if len(sys.argv) < 2:
                raise SystemExit("python-agent: missing <name> argv")
            name = sys.argv[1]
        self.name = name
        self._agent_dir = os.path.join(AGENT_ROOT, name)
        if not os.path.isdir(self._agent_dir):
            raise SystemExit(
                f"python-agent: {self._agent_dir} missing — "
                "did you `agentctl create` it first?")
        os.chdir(self._agent_dir)
        self.handlers: dict[str, Callable] = {}
        self._task_seq = self._load_max_task_seq() + 1
        self._kind, self._mount = _resolve_transport(self._agent_dir)
        self._listener: Optional[socket.socket] = None
        self._inbox_fd: int = -1
        self._shutdown = False
        self._setup_listener()
        self._set_status("idle")
        profile = self._read_profile()
        self.log(
            f"python-agent started pid={os.getpid()} "
            f"transport={self._kind} profile={profile} "
            "dispatch=persistent artifact_policy=overwrite "
            "idle_timeout=0")

    # ---- on-disk helpers --------------------------------------------------

    def _read_profile(self) -> str:
        v = _read_text(os.path.join(self._agent_dir, "profile"))
        return (v.strip() if v else "worker") or "worker"

    def _set_status(self, s: str) -> None:
        _atomic_write(os.path.join(self._agent_dir, "status"), s + "\n")

    def log(self, line: str) -> None:
        _append_file(os.path.join(self._agent_dir, "audit.log"),
                     f"{_iso_now()} pid={os.getpid()} {line}\n".encode())

    def _load_max_task_seq(self) -> int:
        tdir = os.path.join(self._agent_dir, "tasks")
        if not os.path.isdir(tdir):
            return 0
        m = 0
        pat = re.compile(r"^\d{8}T\d{6}Z-(\d{4,})$")
        for entry in os.listdir(tdir):
            mo = pat.match(entry)
            if mo:
                n = int(mo.group(1))
                if n > m:
                    m = n
        return m

    def _alloc_task_id(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        n = self._task_seq
        self._task_seq += 1
        return f"{ts}-{n:04d}"

    # ---- transport listener ----------------------------------------------

    def _setup_listener(self) -> None:
        if self._kind == "uds":
            sock_path = os.path.join(self._agent_dir, "agent.sock")
            try:
                os.unlink(sock_path)
            except FileNotFoundError:
                pass
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(sock_path)
            os.chmod(sock_path, 0o600)
            s.listen(8)
            self._listener = s
        elif self._kind == "agentfs":
            mount = self._mount or "/mnt/agentfs"
            # Same two steps as common.c::agentfs_listen:
            with open(os.path.join(mount, "register"), "wb") as f:
                f.write(self.name.encode() + b"\n")
            inbox = os.path.join(mount, "agents", self.name, "inbox")
            self._inbox_fd = os.open(inbox, os.O_RDWR)
        else:
            raise SystemExit(f"python-agent: unknown transport: {self._kind}")

    # ---- outbound send (mirrors send_to_agent_ex) ------------------------

    def _send(self, target: str, verb: str,
              reply_to: str = "", task_id: str = "",
              payload: bytes = b"") -> None:
        target_dir = os.path.join(AGENT_ROOT, target)
        kind, mount = _resolve_transport(target_dir)
        frame = _build_frame(verb, payload, reply_to, task_id)
        if kind == "uds":
            sock_path = os.path.join(target_dir, "agent.sock")
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(sock_path)
                s.sendall(frame)
                s.close()
            except (FileNotFoundError, ConnectionRefusedError):
                self.log(f"send -> {target} skipped (no listener)")
        else:
            inbox = os.path.join(mount or "/mnt/agentfs",
                                 "agents", target, "inbox")
            fd = os.open(inbox, os.O_WRONLY)
            try:
                os.write(fd, frame)
            finally:
                os.close(fd)

    # ---- public API -------------------------------------------------------

    def handler(self, verb: str) -> Callable:
        """Decorator: register `func` as the handler for `verb`."""
        def deco(func: Callable) -> Callable:
            self.handlers[verb] = func
            return func
        return deco

    # ---- main loop --------------------------------------------------------

    def _install_signals(self) -> None:
        # PEP 475: blocking syscalls retry on EINTR unless the handler raises.
        # So we route signals through a self-pipe: the handler writes a byte,
        # and the main loop selects on both the listener and the pipe — any
        # signal wakes the loop without us needing to raise.
        r, w = os.pipe()
        os.set_blocking(r, False)
        os.set_blocking(w, False)
        signal.set_wakeup_fd(w)
        self._wakeup_r = r
        self._wakeup_w = w

        def _term(_signum, _frame):
            self._shutdown = True
        signal.signal(signal.SIGTERM, _term)
        signal.signal(signal.SIGINT, _term)

    def _dispatch(self, msg: dict) -> None:
        verb = msg["verb"]
        sender = msg.get("reply_to") or "?"
        plen = len(msg["payload"])
        self.log(f"recv verb={verb} from={sender} pid=0 uid=0 len={plen}")
        if verb == "ping":
            return  # parity with the C reviewer: ping never creates a task
        handler = self.handlers.get(verb)
        if handler is None:
            self.log(f"unknown verb: {verb}")
            return
        task = Task(self, msg)
        self.log(f"task created {task.task_id} verb={verb} from={sender}")
        task._set_state("running")
        task.event("running")
        try:
            self._set_status("processing")
            handler(task)
            if not task._completed:
                task.complete()
        except CapabilityError:
            pass  # task already marked failed by the decorator
        except Exception as exc:
            task.fail(f"{type(exc).__name__}: {exc}")
        finally:
            self._set_status("idle")
        if sender != "?":
            corr = task.incoming_task_id or task.task_id
            try:
                with open(os.path.join(task._dir, "result"), "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                body = b""
            self._send(sender, "result", reply_to=self.name,
                       task_id=corr, payload=body)
            self.log(f"reply -> {sender} ok (task={corr})")

    def run(self) -> None:
        self._install_signals()
        try:
            if self._kind == "uds":
                self._run_uds()
            else:
                self._run_agentfs()
        finally:
            self._set_status("stopping")
            self.log("python-agent shutting down")
            if self._kind == "uds" and self._listener:
                try:
                    self._listener.close()
                except OSError:
                    pass
                try:
                    os.unlink(os.path.join(self._agent_dir, "agent.sock"))
                except FileNotFoundError:
                    pass
            elif self._inbox_fd >= 0:
                try:
                    os.close(self._inbox_fd)
                except OSError:
                    pass
            self._set_status("stopped")

    def _drain_wakeup(self) -> None:
        try:
            while os.read(self._wakeup_r, 4096):
                pass
        except BlockingIOError:
            pass

    def _run_uds(self) -> None:
        assert self._listener is not None
        sel = selectors.DefaultSelector()
        sel.register(self._listener.fileno(), selectors.EVENT_READ, "listener")
        sel.register(self._wakeup_r, selectors.EVENT_READ, "wakeup")
        while not self._shutdown:
            try:
                events = sel.select()
            except InterruptedError:
                continue
            for key, _mask in events:
                if key.data == "wakeup":
                    self._drain_wakeup()
                    continue
                try:
                    conn, _ = self._listener.accept()
                except (BlockingIOError, InterruptedError):
                    continue
                try:
                    msg = _recv_one_frame(conn)
                finally:
                    conn.close()
                if msg is not None:
                    self._dispatch(msg)

    def _run_agentfs(self) -> None:
        sel = selectors.DefaultSelector()
        sel.register(self._inbox_fd, selectors.EVENT_READ, "inbox")
        sel.register(self._wakeup_r, selectors.EVENT_READ, "wakeup")
        cap = MAX_PAYLOAD + 4096
        while not self._shutdown:
            try:
                events = sel.select()
            except InterruptedError:
                continue
            for key, _mask in events:
                if key.data == "wakeup":
                    self._drain_wakeup()
                    continue
                try:
                    data = os.read(self._inbox_fd, cap)
                except (BlockingIOError, InterruptedError):
                    continue
                if not data:
                    continue
                msg, _used = _parse_frame(data)
                if msg is None:
                    self.log(f"agentfs_recv: malformed frame ({len(data)} bytes)")
                    continue
                self._dispatch(msg)
