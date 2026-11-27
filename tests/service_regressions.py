"""Run as non-root with /sys/fs/cgroup/agents delegated to that user."""
import os
import pathlib
import signal
import sys
import time
import unittest
import uuid
import runtime_regressions as base

@unittest.skipUnless(sys.platform == "linux" and os.access("/sys/fs/cgroup/agents", os.W_OK),
                     "requires delegated Linux cgroup v2")
class ServiceRegressions(unittest.TestCase):
    setUp = base.RuntimeRegressions.setUp
    cli = base.RuntimeRegressions.cli
    create = base.RuntimeRegressions.create
    start = base.RuntimeRegressions.start

    def tearDown(self):
        # CLI stop deletes the agent directory. Always release the test daemon,
        # including after a failed assertion or a prior successful stop.
        try:
            if hasattr(self, "name"):
                cg = pathlib.Path("/sys/fs/cgroup/agents") / self.name
                try:
                    if (self.root / "agents" / self.name).exists():
                        self.cli("stop", self.name)
                finally:
                    if (cg / "cgroup.kill").exists():
                        (cg / "cgroup.kill").write_text("1\n")
                        base.eventually(lambda: "populated 0\n" in (cg / "cgroup.events").read_text())
                        cg.rmdir()
        finally:
            base.RuntimeRegressions.tearDown(self)

    def service(self, mode, timeout=30000):
        self.name = "svc-" + uuid.uuid4().hex[:12]
        directory = self.create(self.name, mode)
        (directory / "config/config").write_text(
            "cgroup=on\nCGROUP_MEMORY_MAX=67108864\nCGROUP_PIDS_MAX=16\nCGROUP_CPU_MAX=10000/100000\nseccomp=minimal\nenforce_fs=landlock\n")
        (directory / "config/service_timeout_ms").write_text(str(timeout) + "\n")
        (directory / "config/service_request_timeout_ms").write_text("6000\n")
        self.cli("set-restart-policy", self.name, "service")
        return directory

    def test_25_clean_fresh_workers(self):
        directory = self.service("service-clean")
        self.start(self.name)
        completions = directory / "data/completions"
        base.eventually(lambda: completions.exists() and len(completions.read_text().splitlines()) >= 25, 20)
        pids = completions.read_text().splitlines()
        self.assertGreaterEqual(len(set(pids)), 25)
        count = directory / "runtime/restart_count"
        self.assertTrue(not count.exists() or count.read_text().strip() == "0")
        self.cli("stop", self.name)
        self.assertFalse(any(base.alive(int(pid)) for pid in pids))
        self.assertIsNone(self.daemon.poll())

    def test_idle_timeout_kills_subtree_and_restarts(self):
        directory = self.service("descendants", 500)
        # This test isolates the cgroup lifecycle. Minimal seccomp forbids fork;
        # the separate memfd test checks the production syscall profile.
        config = directory / "config/config"
        config.write_text(config.read_text().replace("seccomp=minimal", "seccomp=off"))
        self.start(self.name)
        childfile = directory / "data/child.pid"
        base.eventually(childfile.exists)
        child = int(childfile.read_text())
        base.eventually(lambda: not base.alive(child), 4)
        base.eventually(lambda: childfile.exists() and int(childfile.read_text()) != child, 4)
        count = directory / "runtime/restart_count"
        self.assertTrue(not count.exists() or int(count.read_text()) == 0)
        self.assertIsNone(self.daemon.poll())

    def test_minimal_seccomp_allows_sealed_memory(self):
        directory = self.service("service-memfd")
        self.start(self.name)
        base.eventually(lambda: (directory / "data/memfd-ready").exists())
        self.assertEqual((directory / "data/memfd-ready").read_text().strip(), "sealed")

if __name__ == "__main__":
    unittest.main(verbosity=2)
