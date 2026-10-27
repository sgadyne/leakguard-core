import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy import build_bundle, installer


class MacWorkerPolicyConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lg-deploy-config-")
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.template = Path(__file__).resolve().parents[1] / "deploy" / "default-config.json"
        self.release = self.root / "releases" / "0.2.0-alpha.1"
        self.manifest = {"target_platform": "macos-arm64"}

    def tearDown(self):
        self.temporary.cleanup()

    def configure(self, value=None):
        config = self.state / "config.json"
        if value is not None:
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(json.dumps(value), encoding="utf-8")
        with patch.object(installer.sys, "platform", "darwin"):
            installer._ensure_default_config(self.state, self.template, self.release, self.manifest)
        return json.loads(config.read_text(encoding="utf-8"))

    def test_new_mac_config_uses_supervised_policy(self):
        config = self.configure()
        self.assertEqual(config["worker_policy"], "supervised-alpha")
        self.assertEqual(config["observation_backend"], "encrypted")

    def test_existing_explicit_valid_policy_is_preserved(self):
        for policy in ("strict", "supervised-alpha"):
            with self.subTest(policy=policy):
                self.state = self.root / policy
                config = self.configure({"worker_policy": policy, "customer_setting": "keep"})
                self.assertEqual(config["worker_policy"], policy)
                self.assertEqual(config["customer_setting"], "keep")

    def test_existing_missing_policy_gets_mac_default(self):
        config = self.configure({"customer_setting": "keep"})
        self.assertEqual(config["worker_policy"], "supervised-alpha")
        self.assertEqual(config["customer_setting"], "keep")

    def test_invalid_existing_policy_is_rejected_without_rewrite(self):
        for policy in ("unknown-policy", [], None, 3):
            with self.subTest(policy=policy):
                self.state = self.root / f"invalid-{len(list(self.root.iterdir()))}"
                self.state.mkdir()
                path = self.state / "config.json"
                original = json.dumps({"worker_policy": policy, "kept": True}).encode() + b"\n"
                path.write_bytes(original)
                with patch.object(installer.sys, "platform", "darwin"):
                    with self.assertRaises(installer.DeployError):
                        installer._ensure_default_config(self.state, self.template, self.release, self.manifest)
                self.assertEqual(path.read_bytes(), original)


class SupportManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lg-deploy-support-")
        self.root = Path(self.temporary.name)
        (self.root / "support/docs").mkdir(parents=True)
        self.file = self.root / "support/docs/INSTALL.md"
        self.file.write_text("synthetic install documentation\n", encoding="utf-8")
        digest = hashlib.sha256(self.file.read_bytes()).hexdigest()
        self.manifest = {
            "schema_version": 1,
            "release_version": "0.2.0-alpha.1",
            "source_commit": "unknown",
            "packages": [{"name": "example", "version": "1.0", "filename": "example-1.0.whl",
                          "sha256": "a" * 64}],
            "buddy_command": "leakguard-buddy",
            "service_command": [],
            "wheelhouse": "wheelhouse",
            "target_platform": "linux-x86_64",
            "target_python": "3.11",
            "release_quality": "partial",
            "backend_version": "8.30.1",
            "support_files": [{"path": "support/docs/INSTALL.md", "sha256": digest}],
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_support_file_is_hash_verified_and_install_relative(self):
        verified = installer.validate_support_files(self.root, self.manifest)
        self.assertEqual(verified, [(self.file, Path("support/docs/INSTALL.md"))])

    def test_support_hash_tampering_is_rejected(self):
        self.file.write_text("changed documentation\n", encoding="utf-8")
        with self.assertRaisesRegex(installer.DeployError, "hash mismatch"):
            installer.validate_support_files(self.root, self.manifest)

    def test_manifest_rejects_unsafe_support_paths(self):
        self.manifest["support_files"] = [{"path": "support/../outside.txt", "sha256": "a" * 64}]
        path = self.root / "release.json"
        path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(installer.DeployError, "unsafe support"):
            installer.read_manifest(path)


class CompleteBundleDocumentsTests(unittest.TestCase):
    def test_release_pins_optional_document_parsers_and_build_recipe(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "deploy" / "release-manifest.json").read_text(encoding="utf-8"))
        pins = {name.lower().replace("_", "-"): version
                for name, version in manifest["pinned_distributions"].items()}
        self.assertEqual(pins["pypdf"], "6.21.2")
        self.assertEqual(pins["olefile"], "0.47")
        recipe = (root / "docs" / "INSTALL.md").read_text(encoding="utf-8")
        self.assertIn("pypdf==6.21.2 olefile==0.47", recipe)
        self.assertIn(f"'leakguard-core[documents]=={pins['leakguard-core']}'", recipe)

    def test_alpha_audit_continuation_guide_is_explicit_hashed_support(self):
        self.assertIn("docs/audit-continuation.md", build_bundle.SUPPORT_FILES)


if __name__ == "__main__":
    unittest.main()
