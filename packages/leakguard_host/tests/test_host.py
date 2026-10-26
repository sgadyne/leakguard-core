"""Compact regressions for boundaries the host adapter adds to core scanning."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import plistlib
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
import zipfile
from unittest.mock import patch

from leakguard_core import ScanConfig, ScanReport, CoverageSummary, PolicyDecision
from leakguard_core.models import CoverageIssue, DecisionVerdict, ErrorCode
from leakguard_core.scan_store import MemoryScanStore
from leakguard_host import HostError, HostService, SSHRunner, browse, service_spec
from leakguard_host.ssh import _exchange, _INSTALL


class SessionStore(MemoryScanStore):
    def __init__(self):
        super().__init__()
        self.host_state = {}
        self.checkpoints = 0
        self.fail = False

    def load_host_state(self):
        return deepcopy(self.host_state)

    def save_host_state(self, value):
        if self.fail:
            raise OSError("SYNTHETIC_PRIVATE_ERROR")
        self.host_state = deepcopy(value)
        self.checkpoints += 1


def report(complete=True, code=ErrorCode.BUDGET_EXHAUSTED):
    now = datetime.now(timezone.utc)
    return ScanReport(1, "synthetic-run", now, now, "synthetic-policy", (),
        CoverageSummary(complete, complete, 0, 0 if complete else 3, 0),
        PolicyDecision(DecisionVerdict.ALLOW if complete else DecisionVerdict.INCOMPLETE, () if complete else (code,), "synthetic-policy"),
        () if complete else (CoverageIssue(code, required=True),))


class StubScanner:
    def __init__(self, callback):
        self.callback = callback

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def audit(self, scope, **kwargs):
        return self.callback(scope, kwargs)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = SessionStore()
        self.now = 1_700_000_000

    def host(self, callback=lambda scope, kw: report()):
        return HostService(config=ScanConfig.from_mapping({}), scan_store=self.store,
            clock=lambda: self.now, scanner_factory=lambda **kw: StubScanner(callback))

    def test_missing_encrypted_adapter_rejected(self):
        with self.assertRaisesRegex(HostError, "encrypted-state-required"):
            HostService(config=ScanConfig.from_mapping({}), scan_store=MemoryScanStore())

    def test_root_bounds_symlink_and_cursor_change(self):
        for name in ("a", "b", "c"):
            (self.root / name).mkdir()
        first = browse(self.root, root=self.root, limit=1)
        second = browse(self.root, root=self.root, limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["entries"][0]["name"], second["entries"][0]["name"])
        (self.root / "changed").mkdir()
        with self.assertRaisesRegex(HostError, "cursor-invalid"):
            browse(self.root, root=self.root, cursor=first["next_cursor"])
        if hasattr(Path, "symlink_to"):
            (self.root / "outside").symlink_to(self.root.parent, target_is_directory=True)
            with self.assertRaisesRegex(HostError, "outside-root"):
                browse(self.root / "outside", root=self.root)
        with self.assertRaisesRegex(HostError, "outside-root"):
            browse(self.root.parent, root=self.root)

    def test_one_active_job_pause_restart_resume_and_durable_success(self):
        host = self.host()
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        self.assertEqual(job["id"], host.submit(source["id"])["id"])
        restored = self.host()
        self.assertEqual(restored.job(job["id"])["state"], "paused")
        self.assertEqual(restored.tick()["status"], "idle")
        restored.resume(job["id"])
        self.assertEqual(restored.tick()["status"], "completed")
        self.assertEqual(self.store.host_state["jobs"][job["id"]]["state"], "completed")
        self.assertTrue(restored.sources()[0]["last_success_at"])

    def test_incomplete_slice_does_not_claim_success(self):
        host = self.host(lambda scope, kw: report(False))
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        host.tick()
        state = host.job(job["id"])
        self.assertEqual(state["state"], "queued")
        self.assertEqual(state["coverage"], "incomplete")
        self.assertEqual(state["pending_files"], 3)
        self.assertIsNone(host.sources()[0]["last_success_at"])

    def test_offline_backoff_then_reconnect(self):
        remote = self.root / "share"
        remote.mkdir()
        host = self.host()
        source = host.add_source(remote, kind="mounted")
        job = host.submit(source["id"])
        with patch("leakguard_host.scheduler.navigation.path_status", return_value="offline"):
            self.assertEqual(host.tick()["status"], "backoff")
        self.assertEqual(host.job(job["id"])["coverage"], "incomplete")
        self.assertEqual(host.tick()["status"], "idle")
        self.now += 6
        self.assertEqual(host.tick()["status"], "completed")

    def test_checkpoint_failure_stops_without_acknowledging_completion(self):
        host = self.host()
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        def callback(scope, kw):
            self.store.fail = True
            return report()
        host._scanner_factory = lambda **kw: StubScanner(callback)
        with self.assertRaisesRegex(HostError, "state-checkpoint-failed"):
            host.tick()
        self.assertNotEqual(self.store.host_state["jobs"][job["id"]]["state"], "completed")
        self.assertFalse(host.status()["observation_available"])
        self.assertNotIn("SYNTHETIC_PRIVATE_ERROR", str(host.status()))

    def test_schedule_is_opt_in_and_disabled_source_does_not_start(self):
        host = self.host()
        source = host.add_source(self.root)
        self.now += 1000
        self.assertEqual(host.tick()["status"], "idle")
        host.update_source(source["id"], schedule_seconds=60)
        self.now += 61
        self.assertEqual(host.tick()["status"], "completed")
        host.update_source(source["id"], enabled=False)
        self.now += 61
        self.assertEqual(host.tick()["status"], "idle")

    def test_disabling_source_pauses_admitted_work_and_rejects_resume(self):
        host = self.host()
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        host.update_source(source["id"], enabled=False)
        self.assertEqual(host.job(job["id"])["state"], "paused")
        with self.assertRaisesRegex(HostError, "source-disabled"):
            host.resume(job["id"])
        self.assertEqual(host.tick()["status"], "idle")

    def test_mount_fallback_is_offline_but_same_endpoint_reconnects(self):
        host = self.host()
        with patch("leakguard_host.scheduler.navigation.mount_marker", return_value="same-share"):
            source = host.add_source(self.root, kind="mounted")
        job = host.submit(source["id"])
        # The endpoint identity, rather than a transient inode/device, governs
        # reconnect for a mounted share. A local fallback must never scan.
        host._state["sources"][source["id"]]["root_identity"] = [0, 0]
        with patch("leakguard_host.scheduler.navigation.mount_marker", return_value="local-fallback"):
            self.assertEqual(host.tick()["status"], "backoff")
        self.now += 6
        with patch("leakguard_host.scheduler.navigation.mount_marker", return_value="same-share"):
            self.assertEqual(host.tick()["status"], "completed")

    def test_macos_mount_metadata_uses_supported_no_argument_command(self):
        from leakguard_host.navigation import _mounts
        completed = subprocess.CompletedProcess([], 0, b"/dev/disk1 on / (apfs, local, read-only)\n//server/share on /Volumes/Team Files (smbfs, nodev, mounted by user)\n")
        with patch("leakguard_host.navigation.platform.system", return_value="Darwin"), patch("leakguard_host.navigation.subprocess.run", return_value=completed) as run:
            mounts = _mounts()
        self.assertEqual(run.call_args.args[0], ["/sbin/mount"])
        self.assertEqual(mounts[1]["path"], "/Volumes/Team Files")
        self.assertEqual(mounts[1]["filesystem"], "smbfs")

    def test_cancel_during_slice_wins_and_concurrent_tick_is_busy(self):
        entered, release = threading.Event(), threading.Event()
        def callback(scope, kw):
            entered.set()
            release.wait(2)
            self.assertTrue(kw["cancel"]())
            return report(False, ErrorCode.CANCELLED)
        host = self.host(callback)
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        thread = threading.Thread(target=host.tick)
        thread.start()
        self.assertTrue(entered.wait(2))
        self.assertEqual(host.tick()["status"], "busy")
        host.cancel(job["id"])
        with self.assertRaisesRegex(HostError, "worker-still-running"):
            host.stop(timeout=0)
        release.set()
        thread.join(2)
        self.assertEqual(host.job(job["id"])["state"], "cancelled")
        host.stop(timeout=1)

    def test_service_spec_is_fixed_argv_and_preserves_metacharacters(self):
        command = ["/private/path with spaces/buddy", "serve", "--label", "a;$HOME%"]
        mac = service_spec(command, self.root, platform="darwin")
        self.assertEqual(plistlib.loads(mac["content"].encode())["ProgramArguments"], command)
        linux = service_spec(command, self.root, platform="linux")
        self.assertIn("$$HOME%%", linux["content"])
        self.assertIn("LEAKGUARD_STATE_DIR=", linux["content"])
        self.assertFalse(mac["native_verified"])
        windows = service_spec(command, self.root, platform="windows")
        self.assertIn("<UserId>", windows["content"])
        self.assertIn("<LogonType>InteractiveToken</LogonType>", windows["content"])

    def test_ssh_rejects_options_and_never_returns_arbitrary_output(self):
        runner = SSHRunner()
        with self.assertRaisesRegex(HostError, "ssh-target-invalid"):
            runner.run("-oProxyCommand=evil", "/chosen", python="/private/python")
        with patch("leakguard_host.ssh._exchange", return_value=b'{"secret":"SYNTHETIC_VALUE"}'):
            with self.assertRaisesRegex(HostError, "remote-report-invalid") as raised:
                runner.run("chosen-host", "/chosen", python="/private/python")
            self.assertNotIn("SYNTHETIC_VALUE", str(raised.exception))
        with patch("leakguard_host.ssh._exchange", return_value=report().to_json().encode()):
            self.assertEqual(runner.run("chosen-host", "/chosen", python="/private/python")["coverage"], "complete")

    def test_subprocess_output_limit_and_stderr_redaction(self):
        with self.assertRaisesRegex(HostError, "ssh-output-limit"):
            _exchange([sys.executable, "-c", "print('x'*10000)"], b"", timeout=2, maximum=100)
        with self.assertRaisesRegex(HostError, "ssh-execution-failed") as raised:
            _exchange([sys.executable, "-c", "import sys;sys.stderr.write('SYNTHETIC_VALUE');sys.exit(1)"], b"", timeout=2, maximum=100)
        self.assertNotIn("SYNTHETIC_VALUE", str(raised.exception))

    def test_remote_bundle_rejects_traversal_before_writing(self):
        self.root.chmod(0o700)
        artifact = self.root / "release.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("LeakGuard/../../escape", "SYNTHETIC_VALUE")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, "-c", _INSTALL, str(self.root), digest], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root.parent / "escape").exists())
        self.assertEqual(list((self.root / "content").iterdir()), [])

    def test_remote_bundle_install_receipt_stays_inside_chosen_prefix(self):
        self.root.chmod(0o700)
        artifact = self.root / "release.zip"
        installer = '''import json,pathlib,sys
root=pathlib.Path(sys.argv[sys.argv.index('--prefix')+1])
state=pathlib.Path(sys.argv[sys.argv.index('--state-dir')+1])
print(json.dumps(dict(installed=str(root/'releases/test'),active=True,release_version='test',source_commit=None,runtime_python=str(root/'releases/test/bin/python'),buddy_command=str(root/'releases/test/bin/buddy'),state_dir=str(state))))
'''
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("LeakGuard/release.json", "{}")
            archive.writestr("LeakGuard/deploy/installer.py", installer)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        output = _exchange([sys.executable, "-c", _INSTALL, str(self.root), digest], b"", timeout=5, maximum=4096)
        self.assertEqual(json.loads(output)["state_dir"], str(self.root / "state"))


if __name__ == "__main__":
    unittest.main()
