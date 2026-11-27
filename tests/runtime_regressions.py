"""Linux integration regressions. Each test owns its daemon and data root."""
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import importlib.util
import types

REPO = pathlib.Path(__file__).resolve().parents[1]

def eventually(check, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.05)
    raise AssertionError("condition did not become true within %.1fs" % timeout)

def alive(pid):
    try:
        return pathlib.Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False

@unittest.skipUnless(sys.platform == "linux", "Linux transport required")
class RuntimeRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agentctl-regression-")
        self.root = pathlib.Path(self.temp.name)
        profiles = self.root / "profiles"
        profiles.mkdir()
        (profiles / "worker.profile").write_text(
            "dispatch=persistent\nenforce_fs=off\nseccomp=off\ncgroup=off\n")
        self.env = dict(os.environ, AGENTCTL_ROOT=str(self.root),
                        AGENT_PROFILES_DIR=str(profiles))
        self.log = open(self.root / "daemon.out", "w")
        self.daemon = subprocess.Popen([str(REPO / "agentd")], env=self.env,
                                       stdout=self.log, stderr=self.log)
        self.pids = []
        eventually(lambda: (self.root / "agentd.sock").exists())

    def tearDown(self):
        for pid in self.pids:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.daemon.kill()
        self.daemon.wait(timeout=5)
        self.log.close()
        self.temp.cleanup()

    def cli(self, *args):
        result = subprocess.run([str(REPO / "agentctl"), *args], env=self.env, input="",
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def create(self, name, mode="idle"):
        self.cli("create", name)
        base = self.root / "agents" / name
        (base / "config/restart_policy").write_text("never\n")
        (base / "data/mode").write_text(mode)
        return base

    def start(self, name, executable=None):
        self.cli("start", name, "--exec", str(executable or REPO / "tests/runtime-regression"))
        pid = int((self.root / "agents" / name / "runtime/pid").read_text())
        self.pids.append(pid)
        return pid

    def control(self):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(str(self.root / "agentd.sock"))
            token = (self.root / "agentd.token").read_text().strip()
            conn.sendall(f"AUTH {token} status probe\n".encode())
            self.assertTrue(conn.recv(1024).startswith(b"OK"))

    def test_unread_inbox_does_not_block_supervisor(self):
        self.create("sink")
        self.start("sink")
        base = self.create("probe", "flood")
        self.cli("grant", "probe", "mailbox.send:sink")
        self.start("probe")
        eventually(lambda: (base / "data/busy").exists())
        self.control()

    def test_unread_broker_replies_do_not_block_supervisor(self):
        base = self.create("probe", "unread-replies")
        self.start("probe")
        eventually(lambda: (base / "data/disconnected").exists())
        self.control()

    def test_stop_kills_children_after_leader_exits(self):
        base = self.create("probe", "descendants")
        self.start("probe")
        eventually(lambda: (base / "data/child.pid").exists())
        child = int((base / "data/child.pid").read_text())
        try:
            self.cli("stop", "probe")
            eventually(lambda: not alive(child), timeout=2)
        finally:
            if alive(child):
                os.kill(child, signal.SIGKILL)

    def test_truncated_broker_request_does_not_leak_fds(self):
        descriptors = pathlib.Path(f"/proc/{self.daemon.pid}/fd")
        before = len(list(descriptors.iterdir()))
        for i in range(3):
            name = f"leak{i}"
            self.create(name, "leak")
            self.start(name)
            audit = self.root / "agents" / name / "data/audit.log"
            eventually(lambda: "runtime exited" in audit.read_text())
        self.assertEqual(len(list(descriptors.iterdir())), before)

    def test_python_sdk_private_inbox_and_c_roundtrip(self):
        self.create("sink")
        self.cli("grant", "sink", "mailbox.send:probe")
        self.start("sink", REPO / "reviewer-agent")
        base = self.create("probe")
        # Exercise the default filesystem boundary as well as transport.
        (self.root / "profiles/worker.profile").write_text(
            "dispatch=persistent\nenforce_fs=landlock\nseccomp=off\ncgroup=off\n")
        self.cli("grant", "probe", "fs.read:" + str(REPO))
        self.cli("grant", "probe", "mailbox.send:sink")
        self.start("probe", REPO / "tests/python-runtime.py")
        self.assertFalse((base / "agent.sock").exists())
        self.assertFalse((base / "data/agent.sock").exists())
        self.cli("send", "probe", "review")
        eventually(lambda: (base / "data/roundtrip").exists())
        self.assertEqual((base / "data/received").read_text(), "operator")
        self.assertTrue((base / "data/roundtrip").read_bytes())
        self.assertTrue(list((base / "data/tasks").iterdir()))
        self.assertIn("landlock_status=active", (base / "runtime/enforcement.applied").read_text())

    def request(self, line):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(1)
            conn.connect(str(self.root / "agentd.sock"))
            conn.sendall(line)
            return conn.recv(1024)

    def landlock_profile(self):
        (self.root / "profiles/worker.profile").write_text(
            "dispatch=persistent\nenforce_fs=landlock\nseccomp=off\ncgroup=off\n")

    def test_landlock_file_grant_does_not_grant_sibling(self):
        self.landlock_profile()
        base = self.create("probe", "security-file-grant")
        (self.root / "allowed-file").write_text("before")
        (self.root / "denied-file").write_text("keep")
        self.cli("grant", "probe", "fs.write:/dev/null")
        self.cli("grant", "probe", "fs.write:" + str(self.root / "allowed-file"))
        self.start("probe")
        eventually(lambda: (base / "data/security-ready").exists())
        self.assertEqual((self.root / "allowed-file").read_text(), "ok")
        self.assertEqual((self.root / "denied-file").read_text(), "keep")
        self.assertIn("landlock_status=active", (base / "runtime/enforcement.applied").read_text())

    def test_landlock_blocks_token_truncate_but_allows_data(self):
        self.landlock_profile()
        base = self.create("probe", "security-truncate")
        token = (self.root / "agentd.token").read_bytes()
        self.start("probe")
        eventually(lambda: (base / "data/security-ready").exists())
        self.assertEqual((base / "data/truncate-result").read_text().strip(), "-1 13")
        self.assertEqual((self.root / "agentd.token").read_bytes(), token)
        self.assertEqual((base / "data/truncate-data").stat().st_size, 0)
        self.assertIn("landlock_status=active", (base / "runtime/enforcement.applied").read_text())

    def test_control_uses_validated_memory_token(self):
        self.create("probe")
        token = (self.root / "agentd.token").read_text().strip()
        for replacement in (b"", b"1\n", b"z" * 64, b"a" * 65):
            (self.root / "agentd.token").write_bytes(replacement)
            self.assertIn(b"unauthorized", self.request(b"AUTH  status probe\n"))
            self.assertIn(b"unauthorized", self.request(b"AUTH 1 status probe\n"))
            self.assertTrue(self.request(f"AUTH {token} status probe\n".encode()).startswith(b"OK"))

    def test_daemon_rejects_invalid_token_on_startup(self):
        self.daemon.kill(); self.daemon.wait(timeout=5)
        for data in (b"", b"1\n", b"z" * 64, b"a" * 64 + b"\nextra", b"a" * 63):
            (self.root / "agentd.token").write_bytes(data)
            result = subprocess.run([str(REPO / "agentd")], env=self.env,
                                    capture_output=True, timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"control token", result.stderr)

    def test_forged_cgroup_record_cannot_write_on_exit(self):
        self._forged_cgroup("security-forge-exit")

    def test_forged_cgroup_record_cannot_write_on_forced_stop(self):
        self._forged_cgroup("security-forge-stop")

    def test_cli_kill_does_not_trust_forged_cgroup_record(self):
        self._forged_cgroup("security-forge-stop", operation="kill")

    def _forged_cgroup(self, mode, operation="stop"):
        self.landlock_profile()
        outside = self.root / "outside"; outside.mkdir()
        victim = outside / "victim"; victim.write_text("unchanged\n")
        base = self.create("probe", mode)
        self.cli("start", "probe", "--exec", str(REPO / "tests/runtime-regression"))
        eventually(lambda: (base / "data/security-ready").exists())
        if mode.endswith("stop"):
            pid = int((base / "runtime/pid").read_text()); self.pids.append(pid)
            self.cli(operation, "probe")
            self.assertEqual(victim.read_text(), "unchanged\n")
            eventually(lambda: not alive(pid))
        else:
            eventually(lambda: "runtime exited" in (base / "data/audit.log").read_text())
        self.assertEqual(victim.read_text(), "unchanged\n")

    def test_minimal_seccomp_executes_runtime(self):
        base = self.create("probe", "security-minimal")
        self.cli("start", "probe", "--exec", str(REPO / "tests/runtime-regression"),
                 "--seccomp", "minimal")
        self.pids.append(int((base / "runtime/pid").read_text()))
        eventually(lambda: (base / "data/security-ready").exists())
        self.assertIn("seccomp_status=active", (base / "runtime/enforcement.applied").read_text())

    def test_simple_profile_processes_a_real_review(self):
        (self.root / "profiles/simple.profile").write_bytes((REPO / "profiles/simple.profile").read_bytes())
        self.cli("create", "probe", "--profile", "simple")
        base = self.root / "agents/probe"
        (base / "config/restart_policy").write_text("never\n")
        self.start("probe", REPO / "reviewer-agent")
        self.cli("send", "probe", "review")
        def completed():
            tasks = base / "data/tasks"
            return tasks.exists() and any(p.read_text().strip() == "completed"
                                          for p in tasks.glob("*/status"))
        eventually(completed)
        state = (base / "runtime/enforcement.applied").read_text()
        self.assertIn("landlock_status=active", state)
        self.assertIn("seccomp_status=active", state)

    def test_exec_failure_is_reported_to_cli(self):
        self.create("probe")
        invalid = self.root / "invalid-executable"
        invalid.write_bytes(b"not an executable\n"); invalid.chmod(0o700)
        result = subprocess.run([str(REPO / "agentctl"), "start", "probe", "--exec", str(invalid)],
                                env=self.env, capture_output=True, text=True, timeout=8)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("spawn failed", result.stderr)

    def test_partial_control_request_does_not_block_and_expires(self):
        self.create("probe")
        with socket.socket(socket.AF_UNIX) as slow:
            slow.settimeout(1)
            slow.connect(str(self.root / "agentd.sock"))
            slow.sendall(b"A")
            time.sleep(.1)
            self.control()
            # More bytes must not reset the total request deadline.
            time.sleep(2.5); slow.sendall(b"U")
            time.sleep(2.7)
            self.assertEqual(slow.recv(10), b"")
            self.control()

    def test_enforcement_overrides_survive_runtime_restart(self):
        base = self.create("probe")
        (self.root / "profiles/worker.profile").write_text(
            "dispatch=persistent\nenforce_fs=landlock\nseccomp=off\ncgroup=on\n")
        self.cli("start", "probe", "--exec", str(REPO / "tests/runtime-regression"),
                 "--no-enforce-fs", "--seccomp", "minimal", "--no-cgroup")
        self.pids.append(int((base / "runtime/pid").read_text()))
        requested = (base / "runtime/enforcement.req").read_text()
        self.assertIn("enforce_fs=off", requested)
        self.assertIn("seccomp=minimal", requested)
        self.assertIn("cgroup=off", requested)
        self.cli("restart", "probe")
        self.pids.append(int((base / "runtime/pid").read_text()))
        self.assertEqual((base / "runtime/enforcement.req").read_text(), requested)

    def test_python_artifact_names_are_confined(self):
        spec = importlib.util.spec_from_file_location("agentctl_test_sdk", REPO / "sdk/python/agent.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        task = object.__new__(module.Task)
        task._dir = str(self.root / "task"); task.task_id = "test"
        task._agent = types.SimpleNamespace(log=lambda *_: None)
        artifacts = pathlib.Path(task._dir) / "artifacts"; artifacts.mkdir(parents=True)
        for name in ("../escape", "../../../escape", str(self.root / "escape"),
                     "", ".hidden", "sub/file", "x" * 128, "bad\x00name"):
            with self.assertRaises(ValueError): task.write_artifact(name, b"bad")
        self.assertFalse((self.root / "escape").exists())
        target = self.root / "victim"; target.write_bytes(b"unchanged")
        (artifacts / "result").symlink_to(target)
        task.write_artifact("result", b"safe")
        self.assertEqual(target.read_bytes(), b"unchanged")
        self.assertEqual((artifacts / "result").read_bytes(), b"safe")
        self.assertFalse((artifacts / "result").is_symlink())
        # Do not follow a substituted artifact directory either.
        (artifacts / "result").unlink(); artifacts.rmdir(); artifacts.symlink_to(self.root)
        with self.assertRaises(OSError): task.write_artifact("escape", b"bad")

    def test_layout_does_not_migrate_a_pending_compatibility_link(self):
        base = self.create("probe")
        canonical = base / "config/limits"
        canonical.unlink()
        legacy = base / "limits"
        self.assertEqual(os.readlink(legacy), "config/limits")
        self.start("probe")
        self.assertEqual(os.readlink(legacy), "config/limits")
        self.assertFalse(canonical.is_symlink())

    def test_invalid_cpu_quotas_fail_before_runtime_execution(self):
        invalid = ("garbage", "0/100000", "1000/0", "1000/1000001",
                   "1000/1000/junk", "18446744073709551616/100000",
                   "0000000000000000000001000/1000000garbage", "9" * 400)
        for i, quota in enumerate(invalid):
            with self.subTest(quota=quota):
                self._assert_cgroup_start_failure("badquota%d" % i, quota,
                                                  "cpu.max invalid quota/period")

    def _assert_cgroup_start_failure(self, name, quota, reason):
        base = self.create(name, "security-minimal")
        (base / "config/config").write_text("cgroup=on\nCGROUP_CPU_MAX=" + quota + "\n")
        result = subprocess.run([str(REPO / "agentctl"), "start", name, "--exec",
                                 str(REPO / "tests/runtime-regression")],
                                env=self.env, capture_output=True, text=True, timeout=8)
        pidfile = base / "runtime/pid"
        if pidfile.exists(): self.pids.append(int(pidfile.read_text()))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("spawn failed", result.stderr)
        state = (base / "runtime/enforcement.applied").read_text()
        self.assertIn("cgroup_status=unavailable", state)
        self.assertIn(reason, state)
        self.assertFalse(pidfile.exists())
        self.assertFalse((base / "data/security-ready").exists())
        self.assertEqual((base / "runtime/status").read_text().strip(), "failed")
        self.assertEqual((base / "config/desired_state").read_text().strip(), "stopped")

    def test_configured_cpu_limit_cannot_fall_back_when_cgroups_are_readonly(self):
        if os.access("/sys/fs/cgroup", os.W_OK):
            self.skipTest("requires an unavailable cgroup hierarchy")
        self._assert_cgroup_start_failure("unavailable", "10000/100000", "mkdir")

if __name__ == "__main__":
    if sys.platform != "linux":
        print("skip: Linux integration tests")
        sys.exit(77)
    unittest.main(verbosity=2)
