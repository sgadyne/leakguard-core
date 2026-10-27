"""Compact regressions for boundaries the host adapter adds to core scanning."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
import hashlib
import io
import errno
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time
from tempfile import TemporaryDirectory
import threading
import unittest
import zipfile
from unittest.mock import patch

from leakguard_core import ScanConfig, ScanReport, CoverageSummary, PolicyDecision
from leakguard_core.models import CoverageIssue, DecisionVerdict, ErrorCode
from leakguard_core.scan_store import MemoryScanStore
from leakguard_host import HostError, HostService, SSHRunner, browse, service_spec
from leakguard_host.ssh import _exchange, _INSTALL, _SCAN_SUPERVISOR


class SessionStore(MemoryScanStore):
    def __init__(self):
        super().__init__()
        self.host_state = {}
        self.checkpoints = 0
        self.fail = False
        self.reset_calls = []

    def reset_cycle(self, scope):
        self.reset_calls.append(scope)

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

    def work_identity(self, **kwargs):
        return {"policy_id": "synthetic-policy", "runtime_id": "synthetic-runtime"}


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

    def _change_directory_observably(self, name, previous_mtime_ns):
        (self.root / name).mkdir()
        current = self.root.stat()
        # Directory change timestamps may be deferred or coarse (notably on
        # Windows). Set a distinct real mtime so the fixture exercises the
        # cursor/listing check instead of depending on clock resolution.
        os.utime(self.root, ns=(current.st_atime_ns, previous_mtime_ns + 2_000_000_000))
        self.assertNotEqual(self.root.stat().st_mtime_ns, previous_mtime_ns)

    def test_root_bounds_symlink_and_cursor_change(self):
        for name in ("a", "b", "c"):
            (self.root / name).mkdir()
        previous_mtime_ns = self.root.stat().st_mtime_ns
        first = browse(self.root, root=self.root, limit=1)
        second = browse(self.root, root=self.root, limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["entries"][0]["name"], second["entries"][0]["name"])
        self._change_directory_observably("changed", previous_mtime_ns)
        with self.assertRaisesRegex(HostError, "cursor-invalid"):
            browse(self.root, root=self.root, cursor=first["next_cursor"])
        if hasattr(Path, "symlink_to"):
            (self.root / "outside").symlink_to(self.root.parent, target_is_directory=True)
            with self.assertRaisesRegex(HostError, "outside-root"):
                browse(self.root / "outside", root=self.root)
        with self.assertRaisesRegex(HostError, "outside-root"):
            browse(self.root.parent, root=self.root)

    def test_common_location_can_be_added_using_its_root_kind(self):
        from leakguard_host import roots
        (self.root / "Documents").mkdir()
        with patch("leakguard_host.navigation.Path.home", return_value=self.root), patch("leakguard_host.navigation._mounts", return_value=[]):
            locations = roots()
        self.assertTrue(all(item["kind"] == "local" for item in locations))
        source = self.host().add_source(locations[1]["path"], kind=locations[1]["kind"])
        self.assertEqual(source["kind"], "local")

    @unittest.skipUnless(os.name == "posix", "POSIX directory handles")
    def test_navigation_rejects_ancestor_link_substitution_before_enumeration(self):
        from leakguard_host import navigation
        selected = self.root / "selected"
        selected.mkdir()
        child = selected / "child"
        child.mkdir()
        target = child / "nested"
        target.mkdir()
        (target / "inside.txt").write_text("owned synthetic inside")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "nested").mkdir()
        (outside / "nested/outside.txt").write_text("owned synthetic outside")
        original = navigation._scoped_scandir
        def substitute(target, root, expected):
            child.rename(selected / "previous-child")
            child.symlink_to(outside, target_is_directory=True)
            return original(target, root, expected)
        with patch.object(navigation, "_scoped_scandir", side_effect=substitute):
            result = browse(target, root=selected)
        self.assertNotEqual(result["status"], "available")
        self.assertEqual(result["entries"], [])

    def test_navigation_discards_rows_when_directory_changes_during_listing(self):
        from leakguard_host import navigation
        (self.root / "before").mkdir()
        original = navigation._scoped_scandir
        from contextlib import contextmanager
        @contextmanager
        def change_after_listing(target, root, expected):
            with original(target, root, expected) as entries:
                yield entries
            self._change_directory_observably("after", expected.st_mtime_ns)
        with patch.object(navigation, "_scoped_scandir", side_effect=change_after_listing):
            result = browse(self.root, root=self.root)
        self.assertEqual(result["status"], "directory-changed")
        self.assertEqual(result["entries"], [])

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

    def test_unknown_identity_cannot_spin_after_repeated_resets(self):
        counter = iter(range(20))
        def factory(**kwargs):
            scanner = StubScanner(lambda scope, kw: report(False))
            scanner.work_identity = lambda **kw: {"policy_id": "policy", "runtime_id": str(next(counter))}
            return scanner
        host = HostService(config=ScanConfig.from_mapping({}), scan_store=self.store,
                           scanner_factory=factory, clock=lambda: self.now)
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        for _ in range(4):
            host.tick()
        self.assertEqual(host.job(job["id"])["state"], "paused")
        self.assertEqual(host.job(job["id"])["last_error"], "scan-identity-unstable")
        self.assertIsNone(host.sources()[0]["last_success_at"])

    def test_freshness_offline_and_wake_preserve_paused_job(self):
        host = self.host()
        source = host.add_source(self.root)
        host.update_source(source["id"], schedule_seconds=60)
        self.assertEqual(host.status()["monitoring"][0]["state"], "stale")
        host.reconcile()
        self.assertEqual(host.tick()["status"], "completed")
        self.assertEqual(host.status()["monitoring"][0]["state"], "current")
        self.now += 600
        self.assertTrue(host.status()["monitoring"][0]["stale"])
        with patch("leakguard_host.scheduler.navigation.path_status", return_value="offline"):
            self.assertEqual(host.status()["monitoring"][0]["state"], "offline")
        job = host.submit(source["id"])
        host.pause(job["id"])
        self.assertEqual(host.reconcile()["jobs"], [])
        self.assertEqual(host.job(job["id"])["state"], "paused")
        self.assertEqual(host.status()["monitoring"][0]["state"], "paused")

    def test_nonrequired_omission_does_not_fail_a_partial_slice(self):
        partial = report(False)
        partial = replace(partial, coverage=replace(partial.coverage, omission_count=1),
            issues=partial.issues + (CoverageIssue(ErrorCode.POLICY_OMISSION, required=False, omission_id="operator-exclusion"),))
        host = self.host(lambda scope, kw: partial)
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        self.assertEqual(host.tick()["status"], "queued")
        self.assertIsNone(host.job(job["id"])["last_error"])

    def test_repeated_budget_without_progress_pauses_incomplete(self):
        host = self.host(lambda scope, kw: report(False))
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        for _ in range(4):
            host.tick()
        state = host.job(job["id"])
        self.assertEqual(state["state"], "paused")
        self.assertEqual(state["last_error"], "scan-progress-stalled")
        self.assertEqual(state["coverage"], "incomplete")
        self.assertIsNone(host.sources()[0]["last_success_at"])

    def test_partial_work_is_reset_before_a_changed_policy_can_complete(self):
        identity = {"policy_id": "first-policy", "runtime_id": "first-runtime"}
        complete = False
        def factory(**kwargs):
            scanner = StubScanner(lambda scope, kw: report(complete))
            scanner.work_identity = lambda **kw: dict(identity)
            return scanner
        host = HostService(config=ScanConfig.from_mapping({}), scan_store=self.store,
            scanner_factory=factory, clock=lambda: self.now)
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        host.tick()
        resets = len(self.store.reset_calls)
        identity["runtime_id"] = "changed-plugin-runtime"
        complete = True
        self.assertEqual(host.tick()["status"], "completed")
        self.assertEqual(len(self.store.reset_calls), resets + 1)
        self.assertEqual(host.job(job["id"])["policy_resets"], 1)
        self.assertEqual(host.job(job["id"])["work_identity"], identity)

    def test_missing_identity_contract_fails_without_scanning(self):
        scanned = []
        def factory(**kwargs):
            scanner = StubScanner(lambda scope, kw: scanned.append(True))
            scanner.work_identity = None
            return scanner
        host = HostService(config=ScanConfig.from_mapping({}), scan_store=self.store, scanner_factory=factory)
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        result = host.tick()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(host.job(job["id"])["last_error"], "work-identity-unavailable")
        self.assertEqual(scanned, [])

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

    def test_unexpected_worker_failure_is_visible_and_durably_paused(self):
        host = self.host()
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        with patch.object(host, "_available", side_effect=RuntimeError("SYNTHETIC_PRIVATE_ERROR")):
            host.start()
            host._thread.join(1)
        self.assertEqual(host.status()["worker_error"], "scheduler-failed")
        self.assertEqual(self.store.host_state["jobs"][job["id"]]["state"], "paused")
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

    def test_cancelled_source_cannot_be_removed_until_its_slice_returns(self):
        entered, release = threading.Event(), threading.Event()
        def callback(scope, kw):
            entered.set()
            release.wait(2)
            self.assertTrue(kw["cancel"]())
            return report(False, ErrorCode.CANCELLED)
        host = self.host(callback)
        source = host.add_source(self.root)
        job = host.submit(source["id"])
        result = []
        thread = threading.Thread(target=lambda: result.append(host.tick()))
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            host.cancel(job["id"])
            with self.assertRaisesRegex(HostError, "source-busy"):
                host.remove_source(source["id"])
        finally:
            release.set()
            thread.join(2)
        self.assertEqual(result[0]["status"], "cancelled")
        self.assertTrue(host.remove_source(source["id"])["removed"])
        self.assertEqual(host.sources(), [])

    def test_service_spec_is_fixed_argv_and_preserves_metacharacters(self):
        command = ["/private/path with spaces/buddy", "serve", "--label", "a;$HOME%"]
        mac = service_spec(command, self.root, platform="darwin")
        self.assertEqual(plistlib.loads(mac["content"].encode())["ProgramArguments"], command)
        linux = service_spec(command, self.root, platform="linux")
        self.assertIn("$$HOME%%", linux["content"])
        self.assertIn("LEAKGUARD_STATE_DIR=", linux["content"])
        special_state = service_spec(command, self.root / "literal$state%", platform="linux")
        escaped_state = str(self.root / "literal$state%%").replace("\\", "\\\\")
        self.assertIn('Environment="LEAKGUARD_STATE_DIR=' + escaped_state + '"', special_state["content"])
        with self.assertRaisesRegex(HostError, "service-state-invalid"):
            service_spec(command, self.root / "unsafe\nService=extra", platform="linux")
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

    def test_explicit_deploy_scan_uses_installed_runtime_and_retains_receipt_on_failure(self):
        runner = SSHRunner()
        receipt = {"installed": True, "receipt": {"runtime_python": "/private/runtime/releases/test/venv/bin/python", "state_dir": "/private/state"}}
        with patch.object(runner, "upload"), patch.object(runner, "install", return_value=receipt), patch.object(runner, "run", side_effect=HostError("ssh-timeout")) as run:
            result = runner.deploy("chosen-host", self.root / "selected.zip", "/private", sha256="a" * 64, scan_root="/chosen")
        self.assertTrue(result["installed"])
        self.assertEqual(result["scan"]["coverage"], "incomplete")
        self.assertEqual(run.call_args.kwargs["python"], receipt["receipt"]["runtime_python"])
        self.assertEqual(run.call_args.kwargs["config_path"], "/private/state/config.json")

    def test_ssh_cli_incomplete_report_exits_two(self):
        from leakguard_host.cli import main
        with patch("leakguard_host.cli.SSHRunner") as runner, patch("sys.stdout", new_callable=io.StringIO):
            runner.return_value.run.return_value = {"coverage": "incomplete", "report": {}}
            self.assertEqual(main(["ssh-scan", "chosen-host", "/chosen", "--python", "/private/python"]), 2)

    def test_subprocess_output_limit_and_stderr_redaction(self):
        with self.assertRaisesRegex(HostError, "ssh-output-limit"):
            _exchange([sys.executable, "-c", "print('x'*10000)"], b"", timeout=2, maximum=100)
        with self.assertRaisesRegex(HostError, "ssh-execution-failed") as raised:
            _exchange([sys.executable, "-c", "import sys;sys.stderr.write('SYNTHETIC_VALUE');sys.exit(1)"], b"", timeout=2, maximum=100)
        self.assertNotIn("SYNTHETIC_VALUE", str(raised.exception))

    @unittest.skipUnless(os.name == "posix" and Path("/proc").is_dir(), "Linux process receipt")
    def test_subprocess_descendant_is_reaped_after_leader_exits(self):
        started = time.monotonic()
        script = "import subprocess,sys;p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print(p.pid,flush=True)"
        output = _exchange([sys.executable, "-c", script], b"", timeout=2, maximum=100)
        child = int(output)
        try:
            self.assertLess(time.monotonic() - started, 2)
            status = Path(f"/proc/{child}/stat")
            try:
                state = status.read_text().split()[2]
            except OSError as error:
                # The killed child may disappear between /proc lookup and read.
                # Other failures must remain visible rather than imply reaping.
                if error.errno not in {errno.ENOENT, errno.ESRCH}:
                    raise
            else:
                self.assertIn(state, {"Z", "X"})
        finally:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass

    @unittest.skipUnless(os.name == "posix", "Embedded remote supervisor requires a POSIX target")
    def test_remote_supervisor_reaps_children_in_separate_process_groups(self):
        import psutil
        package = self.root / "fake/leakguard_host"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("")
        (package / "remote_worker.py").write_text('''import json,pathlib,psutil,subprocess,sys,time
request=json.load(sys.stdin)
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],start_new_session=True)
process=psutil.Process(child.pid)
pathlib.Path(request['root'],'child.json').write_text(json.dumps({'pid':child.pid,'started':process.create_time()}))
time.sleep(30)
''')
        # Keep this timeout regression quick; only the supervisor's wall budget
        # changes, while the actual child/process tracking code is exercised.
        supervisor = _SCAN_SUPERVISOR.replace("timeout=seconds+30", "timeout=0.5")
        launch = "import os;os.environ['PYTHONPATH']=" + repr(str(package.parent)) + ";exec(" + repr(supervisor) + ")"
        with self.assertRaisesRegex(HostError, "ssh-execution-failed"):
            _exchange([sys.executable, "-c", launch], json.dumps({"max_seconds": 1, "root": str(self.root)}).encode(), timeout=3, maximum=1000)
        child = json.loads((self.root / "child.json").read_text())
        try:
            process = psutil.Process(child["pid"])
            if process.create_time() == child["started"]:
                self.assertIn(process.status(), {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD})
        except psutil.NoSuchProcess:
            pass
        finally:
            try:
                process = psutil.Process(child["pid"])
                if process.create_time() == child["started"]:
                    process.kill()
            except psutil.Error:
                pass

    @unittest.skipUnless(os.name == "posix", "Embedded remote installer requires a POSIX target")
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

    @unittest.skipUnless(os.name == "posix", "Embedded remote installer requires a POSIX target")
    def test_remote_bundle_install_receipt_stays_inside_chosen_prefix(self):
        self.root.chmod(0o700)
        artifact = self.root / "release.zip"
        installer = '''import json,pathlib,sys
root=pathlib.Path(sys.argv[sys.argv.index('--prefix')+1])
state=pathlib.Path(sys.argv[sys.argv.index('--state-dir')+1])
binary=root/'releases/test/bin';binary.mkdir(parents=True)
(binary/'python').symlink_to(sys.executable)
(binary/'buddy').write_text('synthetic console script')
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
