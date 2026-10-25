"""The built-in parser worker must not import extensions from scan CWD."""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv

from leakguard_core import engine, plugins


def _positive_pdf(text: str) -> bytes:
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        ByteStringObject,
        DecodedStreamObject,
        DictionaryObject,
        NameObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = writer._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    }))
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
    })
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = DecodedStreamObject()
    stream.set_data((f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET").encode("ascii"))
    page[NameObject("/Contents")] = writer._add_object(stream)
    identifier = ByteStringObject(hashlib.sha256(text.encode("utf-8")).digest()[:16])
    writer._ID = ArrayObject((identifier, identifier))
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _fake_shadow(sentinel: Path) -> str:
    return (
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('local shadow imported', encoding='ascii')\n"
        "class _Page:\n"
        "    def extract_text(self): return 'benign synthetic PDF text'\n"
        "class PdfReader:\n"
        "    def __init__(self, *args, **kwargs):\n"
        "        self.is_encrypted = False\n"
        "        self.pages = [_Page()]\n"
    )


class WorkerImportIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="leakguard-worker-import-")
        self.root = Path(self.temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.cwd = self.root / "untrusted-cwd"
        self.cwd.mkdir()
        self.sentinel = self.root / "local-pypdf-imported"
        (self.cwd / "pypdf.py").write_text(_fake_shadow(self.sentinel), encoding="utf-8")
        self.config = self.root / "config.json"
        self.config.write_text("{}\n", encoding="utf-8")
        self.gitconfig = self.root / "gitconfig"
        self.gitconfig.write_text("", encoding="utf-8")

    def tearDown(self):
        self.assertTrue(self.root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.temporary.cleanup()

    def _environment(self, package_root: Path, state: Path) -> dict[str, str]:
        environment = dict(os.environ)
        for key in ("PYTHONHOME", "PYTHONUSERBASE"):
            environment.pop(key, None)
        environment.update({
            "PYTHONPATH": str(package_root),
            "LEAKGUARD_CONFIG": str(self.config),
            "LEAKGUARD_STATE_DIR": str(state),
            "LEAKGUARD_GITLEAKS": str(Path(os.environ.get("LEAKGUARD_GITLEAKS", engine.EXE)).resolve()),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(self.gitconfig),
            "GIT_TERMINAL_PROMPT": "0",
        })
        return environment

    def _scan(self, python: Path, package_root: Path, source: Path, state: Path):
        return subprocess.run(
            [str(python), "-m", "leakguard_core.cli", "scan",
             "--state-dir", str(state), "--format", "json", "--fail-on", "block",
             str(source)],
            cwd=self.cwd,
            env=self._environment(package_root, state),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "optional pypdf parser extra unavailable")
    def test_local_pypdf_cannot_replace_installed_positive_pdf_parser(self):
        marker = "PDF-Import-Isolation-Synthetic-Q7nV5xP2"
        source = self.cwd / "positive.pdf"
        source.write_bytes(_positive_pdf(f'client_secret = "{marker}"'))
        package_root = Path(engine.__file__).resolve().parent.parent
        result = self._scan(sys.executable, package_root, source, self.root / "state-installed")

        self.assertFalse(self.sentinel.exists(), "untrusted CWD pypdf.py was imported by parser worker")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        findings = [finding for row in report["results"] for finding in row["findings"]]
        self.assertIn("literal-client-secret", {finding["rule"] for finding in findings})
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_missing_pypdf_stays_dependency_unavailable_despite_local_shadow(self):
        # A dedicated venv carries just the checked-out/installed core and its
        # required packaging library. It intentionally has no documents extra.
        runtime = self.root / "parser-free-venv"
        venv.EnvBuilder(with_pip=False, system_site_packages=False).create(runtime)
        python = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        probe = subprocess.run(
            [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        site = Path(probe.stdout.strip())
        package_source = Path(engine.__file__).resolve().parent
        shutil.copytree(package_source, site / "leakguard_core",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        packaging = importlib.util.find_spec("packaging")
        self.assertIsNotNone(packaging)
        shutil.copytree(Path(packaging.origin).parent, site / "packaging",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        distribution = importlib.metadata.distribution("packaging")
        shutil.copytree(distribution._path, site / distribution._path.name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        self.assertFalse((site / "pypdf").exists())

        # The PDF header is enough to select the PDF parser. If it imports the
        # local shadow, that fake parser reports complete benign text instead.
        source = self.cwd / "positive-with-parser-absent.pdf"
        source.write_bytes(b"%PDF-1.4\n%synthetic parser-unavailable probe\n")
        result = self._scan(python, site, source, self.root / "state-absent")

        self.assertFalse(self.sentinel.exists(), "untrusted CWD pypdf.py was imported by parser worker")
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        issue_codes = {
            issue["code"]
            for row in report["results"]
            for issue in row["issues"]
        }
        self.assertIn("dependency-unavailable", issue_codes)
        self.assertFalse(report["coverage"]["required_complete"])
        self.assertNotIn("literal-client-secret", result.stdout)
        self.assertNotIn(str(self.sentinel), result.stdout + result.stderr)

    def test_explicit_plugin_still_runs_without_cwd_worker_spoof(self):
        fake_core = self.cwd / "leakguard_core"
        fake_core.mkdir()
        (fake_core / "__init__.py").write_text("", encoding="utf-8")
        (fake_core / "plugin_worker.py").write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            f"Path({str(self.sentinel)!r}).write_text('local worker imported', encoding='ascii')\n"
            "request = json.loads(sys.stdin.buffer.read().decode('utf-8'))\n"
            "if request.get('operation') == 'inspect':\n"
            "    response = {'api_version': 1, 'manifest': None, 'has_extract': False}\n"
            "else:\n"
            "    response = {'findings': [{'rule': 'spoofed-worker-rule', 'line': 1, 'severity': 'review'}]}\n"
            "sys.stdout.write(json.dumps(response, separators=(',', ':')))\n",
            encoding="utf-8",
        )
        extensions = self.root / "extensions"
        extensions.mkdir()
        (extensions / "trusted_fixture_plugin.py").write_text(
            "from leakguard_core.plugins import Finding\n"
            "API_VERSION = 1\n"
            "class Detector:\n"
            "    def detect(self, text, path, part):\n"
            "        if 'synthetic-plugin-import-marker' in text:\n"
            "            yield Finding('trusted-fixture-rule', 1, 'review')\n"
            "def create_plugin(options): return Detector()\n",
            encoding="utf-8",
        )

        original_cwd = Path.cwd()
        sys.path.insert(0, str(extensions))
        try:
            os.chdir(self.cwd)
            loaded = plugins.load([{"module": "trusted_fixture_plugin"}])
            findings = list(plugins.detect(
                loaded, "synthetic-plugin-import-marker", Path("fixture.txt"), "text",
                format_id="text",
            ))
        finally:
            os.chdir(original_cwd)
            if sys.path and sys.path[0] == str(extensions):
                sys.path.pop(0)

        self.assertFalse(self.sentinel.exists(), "untrusted CWD plugin_worker.py was imported")
        self.assertEqual([finding.rule for finding in findings], ["trusted-fixture-rule"])


if __name__ == "__main__":
    unittest.main()
