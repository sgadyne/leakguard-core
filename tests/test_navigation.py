from __future__ import annotations

import base64
import os
from pathlib import Path
import tempfile
import time
import sys
import unittest

from leakguard_core.navigation import Navigation, NavigationError, _component_from_wire, _loads
from leakguard_core.sources import AcquisitionError, FilesystemBoundary


ROOT = Path(__file__).resolve().parents[1]
BUILT_HELPER = ROOT / "native" / "scan_walk" / "target" / "release" / "leakguard-scan-walk"
HELPER = Path(os.environ["LEAKGUARD_SCAN_WALKER"]) if os.environ.get("LEAKGUARD_SCAN_WALKER") else BUILT_HELPER


class NavigationTests(unittest.TestCase):
    def _backends(self):
        backends = [("python", None)]
        if HELPER.is_file() and os.access(HELPER, os.X_OK) and os.name == "posix":
            backends.append(("native", HELPER))
        return backends

    def _entries(self, navigation, path, **kwargs):
        with navigation.scandir(path, **kwargs) as entries:
            return list(entries)

    def test_hidden_ignored_and_symlink_entries_are_listed_without_following(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
            (root / "ignored.txt").write_text("ignored", encoding="utf-8")
            (root / ".hidden").write_text("hidden", encoding="utf-8")
            (root / "ordinary").write_text("ordinary", encoding="utf-8")
            (root / "folder").mkdir()
            if hasattr(os, "symlink"):
                os.symlink(root / "ordinary", root / "link")
                os.symlink(root, root / "loop", target_is_directory=True)
            for backend, helper in self._backends():
                with self.subTest(backend=backend), Navigation(helper) as nav:
                    entries = self._entries(nav, root)
                    names = [entry.name for entry in entries]
                    self.assertEqual(names, sorted(names, key=os.fsencode))
                    self.assertIn(".hidden", names)
                    self.assertIn("ignored.txt", names)
                    by_name = {entry.name: entry for entry in entries}
                    self.assertTrue(by_name["folder"].is_dir())
                    if "link" in by_name:
                        self.assertTrue(by_name["link"].is_symlink())
                        with self.assertRaises(NavigationError):
                            by_name["link"].is_file(follow_symlinks=True)
                    if "loop" in by_name:
                        self.assertTrue(by_name["loop"].is_symlink())

    def test_stat_preserves_nanoseconds_and_capabilities_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "item"
            path.write_text("x", encoding="utf-8")
            expected = path.stat(follow_symlinks=False)
            for backend, helper in self._backends():
                with self.subTest(backend=backend), Navigation(helper) as nav:
                    capabilities = nav.capabilities()
                    self.assertEqual(capabilities["follow_links"], False)
                    self.assertEqual(capabilities["hidden_entries"], True)
                    entry = self._entries(nav, root)[0]
                    self.assertEqual(entry.stat().st_mtime_ns, expected.st_mtime_ns)
                    self.assertEqual(entry.stat().st_atime_ns, expected.st_atime_ns)

    def test_boundary_fd_and_same_filesystem_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "child").mkdir()
            boundary = FilesystemBoundary(root)
            for backend, helper in self._backends():
                with self.subTest(backend=backend), Navigation(helper) as nav:
                    entries = self._entries(nav, root, boundary=boundary,
                                            same_file_system=True)
                    self.assertEqual([entry.name for entry in entries], ["child"])

    def test_limits_deadlines_and_cancellation_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("a", "b"):
                (root / name).write_text(name, encoding="utf-8")
            for backend, helper in self._backends():
                with self.subTest(backend=backend), Navigation(helper, max_entries=1) as nav:
                    with self.assertRaises(NavigationError) as limited:
                        self._entries(nav, root)
                    self.assertEqual(limited.exception.code, "entry-limit")
                    with self.assertRaises(NavigationError) as cancelled:
                        self._entries(nav, root, cancel=lambda: True)
                    self.assertEqual(cancelled.exception.code, "cancelled")
                    with self.assertRaises(NavigationError) as expired:
                        self._entries(nav, root, deadline=time.monotonic() - 1)
                    self.assertEqual(expired.exception.code, "deadline-exhausted")
                    with self.assertRaises(NavigationError) as nonfinite:
                        self._entries(nav, root, deadline=float("inf"))
                    self.assertEqual(nonfinite.exception.code, "deadline-exhausted")

    def test_requested_missing_helper_fails_without_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "does-not-exist"
            with self.assertRaises(NavigationError) as failure:
                Navigation(missing)
            self.assertEqual(failure.exception.code, "helper-unavailable")

    def test_helper_handshake_rejects_boolean_protocol_version(self):
        if os.name != "posix":
            self.skipTest("native helper is POSIX-only")
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "malformed-helper"
            ready = ('{"schema_version":true,"kind":"ready","helper_version":"0.1.0",'
                     '"ignore_version":"0.4.33","secure_fd":true,"hidden_entries":true,'
                     '"ignore_filters":false,"follow_links":false,"same_file_system":true,'
                     '"direct_entries_only":true}')
            fake.write_text(
                f"#!{sys.executable}\nimport signal, socket, sys\n"
                f"channel = socket.socket(fileno=int(sys.argv[2]))\n"
                f"channel.sendall({(ready + chr(10))!r}.encode())\nsignal.pause()\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            with self.assertRaises(NavigationError) as failure:
                Navigation(fake)
            self.assertEqual(failure.exception.code, "helper-handshake-invalid")

    def test_boundary_denial_and_root_retarget_are_surfaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / "private").write_text("synthetic", encoding="utf-8")
            boundary = FilesystemBoundary(root)
            old_root = base / "old-root"
            root.rename(old_root)
            root.symlink_to(outside, target_is_directory=True)
            for backend, helper in self._backends():
                with self.subTest(backend=backend), Navigation(helper) as nav:
                    with self.assertRaises(AcquisitionError) as failure:
                        with nav.scandir(root, boundary=boundary) as entries:
                            list(entries)
                    self.assertEqual(failure.exception.code, "source-unavailable")

    def test_early_close_and_cancellation_leave_helper_ready_for_next_request(self):
        if not (HELPER.is_file() and os.access(HELPER, os.X_OK) and os.name == "posix"):
            self.skipTest("native helper not built")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(8):
                (root / f"{index:02d}").write_text("synthetic", encoding="utf-8")
            with Navigation(HELPER) as nav:
                process = nav._process
                with nav.scandir(root) as entries:
                    next(entries)
                with self.assertRaises(NavigationError) as cancelled:
                    with nav.scandir(root, cancel=lambda: True) as entries:
                        next(entries)
                self.assertEqual(cancelled.exception.code, "cancelled")
                self.assertEqual(len(self._entries(nav, root)), 8)
                self.assertIsNotNone(process)
                self.assertIsNone(process.poll())
            self.assertIsNotNone(process.poll())

    def test_duplicate_wire_fields_and_path_components_are_rejected(self):
        with self.assertRaises(NavigationError) as duplicate:
            _loads(b'{"kind":"entry","kind":"done"}')
        self.assertEqual(duplicate.exception.code, "helper-response-invalid")
        wire = {"name_b64": base64.b64encode(b"../escape").decode("ascii"),
                "kind": "file", "mode": 0o100644, "size": 0,
                "atime_ns": 0, "mtime_ns": 0, "ctime_ns": 0,
                "device": 1, "inode": 1, "nlink": 1, "uid": 1, "gid": 1}
        with self.assertRaises(NavigationError) as path:
            _component_from_wire(wire, Path("/safe"))
        self.assertEqual(path.exception.code, "helper-path-invalid")
        wire["name_b64"] = base64.b64encode(b"safe").decode("ascii")
        wire["kind"] = []
        with self.assertRaises(NavigationError) as invalid_kind:
            _component_from_wire(wire, Path("/safe"))
        self.assertEqual(invalid_kind.exception.code, "helper-response-invalid")


if __name__ == "__main__":
    unittest.main()
