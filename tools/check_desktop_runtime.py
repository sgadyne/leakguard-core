#!/usr/bin/env python3
"""Check a built native payload using only an explicitly new synthetic profile.

No default profile, legacy service, kill-by-port or real repository is touched.
Only status metadata are written to the receipt. Native Electron acceptance is
separate; this exercises the exact bundled CPython/venv/backend/API boundary.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urlencode
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_product_journey as journey


class CheckFailure(Exception):
    pass


def require(value, code):
    if not value:
        raise CheckFailure(code)


class DesktopChild:
    def __init__(self, python, state, config, cwd):
        env = journey._child_env()
        env.update(LEAKGUARD_STATE_DIR=str(state), LEAKGUARD_CONFIG=str(config))
        self.process = subprocess.Popen([str(python), "-I", "-B", "-X", "utf8", "-m", "leakguard_buddy.desktop",
                                         "--state-dir", str(state), "--config", str(config)],
                                        cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self.lines = queue.Queue(maxsize=64)
        self.errors = bytearray()
        self.sequence = 0
        self.threads = [threading.Thread(target=self.read_stdout, daemon=True),
                        threading.Thread(target=self.read_stderr, daemon=True)]
        for thread in self.threads:
            thread.start()

    def read_stdout(self):
        while True:
            line = self.process.stdout.readline(16385)
            if not line:
                self.lines.put(None)
                return
            try:
                value = json.loads(line) if len(line) <= 16384 else {"type": "invalid"}
            except ValueError:
                value = {"type": "invalid"}
            self.lines.put(value)

    def read_stderr(self):
        while True:
            value = self.process.stderr.read(4096)
            if not value:
                return
            if len(self.errors) < 256000:
                self.errors.extend(value[:256000 - len(self.errors)])

    def next(self, timeout=30):
        try:
            value = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise CheckFailure("desktop-control-timeout") from None
        require(isinstance(value, dict), "desktop-control-closed")
        return value

    def command(self, operation):
        self.sequence += 1
        request = {"id": self.sequence, "op": operation}
        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        self.process.stdin.flush()
        value = self.next()
        require(value.get("id") == self.sequence and value.get("ok") is True, "desktop-control-" + operation + "-failed")
        return value.get("result")

    def stop(self):
        if self.process.poll() is None:
            try:
                self.command("shutdown")
            except (CheckFailure, OSError, BrokenPipeError):
                self.process.stdin.close()  # Parent EOF requests the same safe owned shutdown.
            try:
                self.process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                return False
        for thread in self.threads:
            thread.join(timeout=2)
        return self.process.returncode == 0


def prepare(resources, profile, *, expected_error=None):
    manifest = json.loads((resources / "desktop-manifest.json").read_text())
    result = subprocess.run([str(resources / manifest["pythonExecutable"]), "-I", "-B", "-X", "utf8",
                             str(resources / "bootstrap.py"), "--resources", str(resources), "--data-dir", str(profile)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    require(len(result.stdout) <= 65536, "preparer-output-unbounded")
    try:
        lines = [json.loads(line) for line in result.stdout.splitlines()]
    except ValueError:
        raise CheckFailure("preparer-protocol-invalid") from None
    if expected_error:
        require(result.returncode != 0 and lines[-1] == {"type": "error", "code": expected_error}, "preparer-error-mismatch")
        return lines
    require(result.returncode == 0, "private-runtime-preparation-failed")
    ready = [line for line in lines if line.get("type") == "runtime-ready"]
    require(len(ready) == 1 and lines[-1] == ready[0], "preparer-ready-invalid")
    receipt = ready[0]
    for key in ("python", "stateDir", "config"):
        require(Path(receipt[key]).is_relative_to(profile) and Path(receipt[key]).resolve().is_relative_to(profile), "preparer-path-escape")
    return receipt, lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True, help="new absolute harness-owned directory")
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--keep-profile", action="store_true")
    parser.add_argument("--browser-inputs", type=Path, help="optional prepared native-browser-inputs.json")
    args = parser.parse_args()
    work = args.work.absolute()
    require(work.is_absolute() and work.resolve() == work and not work.exists(), "new-owned-work-directory-required")
    work.mkdir(mode=0o700, parents=True)
    profile = work / "desktop-profile"
    resources = args.resources.resolve(strict=True)
    manifest_before = (resources / "desktop-manifest.json").read_bytes()
    started = time.monotonic()
    checks, details = {}, {}
    receipt = {"schemaVersion": 1, "passed": False, "scope": "native installed runtime/API; Electron native acceptance separate",
               "checks": checks, "details": details}
    children = []
    safe_cleanup = True
    sensitive = []
    all_bodies = []
    try:
        runtime, stages = prepare(resources, profile)
        manifest = json.loads(manifest_before)
        details.update(sourceCommit=manifest["sourceCommit"], runtimeId=manifest["runtimeId"], target=manifest["target"])
        python, state, config = (Path(runtime[key]) for key in ("python", "stateDir", "config"))
        checks["immutable_resources_verified_and_private_venv_prepared"] = True
        installed_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in resources.glob("backend/LeakGuard/wheelhouse/*.whl")}
        details["bundledWheelHashes"] = installed_hashes
        child = DesktopChild(python, state, config, profile)
        children.append(child)
        ready = child.next()
        require(ready.get("type") == "ready" and ready.get("protocol") == 1 and "token" not in ready, "desktop-ready-invalid")
        client = journey.BuddyClient(ready["origin"], timeout=20)
        require(client.request("GET", "/api/status", auth=False)[0] == 401, "unauthenticated-api-accepted")
        require(client.request("GET", "/api/status", auth=False, host="127.0.0.1:1")[0] == 421, "wrong-host-accepted")
        token = child.command("bootstrap")["token"]
        sensitive.append(token.encode())
        require(client.request("POST", "/__bootstrap", {"token": token}, auth=False,
                               origin="http://localhost", csrf=False)[0] == 403, "wrong-origin-accepted")
        client.exchange(token)
        require(client.request("GET", "/api/session")[1].get("csrf") == client.csrf, "session-recovery-invalid")
        require(client.request("POST", "/api/vault/lock", {}, csrf=False)[0] == 403, "missing-csrf-accepted")
        checks["auth_host_origin_csrf_session"] = True
        require(not (state / "buddy-launch.url").exists(), "desktop-created-browser-token-file")
        duplicate = DesktopChild(python, state, config, profile)
        children.append(duplicate)
        duplicate_ready = duplicate.next()
        require(duplicate_ready.get("type") == "error" and duplicate_ready.get("code") == "profile-in-use", "duplicate-profile-not-refused")
        duplicate.process.stdin.close()
        duplicate.process.wait(timeout=10)
        checks["backend_ownership_while_stores_locked"] = True
        observation_phrase = "Desktop synthetic observation passphrase " + uuid.uuid4().hex
        vault_phrase = "Desktop synthetic credential passphrase " + uuid.uuid4().hex
        backup_phrase = "Desktop synthetic backup passphrase " + uuid.uuid4().hex
        secret = "DesktopSyntheticSecret" + uuid.uuid4().hex
        sensitive.extend(value.encode() for value in (observation_phrase, vault_phrase, backup_phrase, secret))
        require(client.request("POST", "/api/observations/create", {"passphrase": observation_phrase})[0] == 201, "scan-store-create-failed")
        require(client.request("POST", "/api/vault/create", {"passphrase": vault_phrase})[0] == 201, "vault-create-failed")
        fixture_text, expected_rule, _ = journey._load_fixture()
        sensitive.append(fixture_text.encode())
        source = work / "source"
        source.mkdir(mode=0o700)
        fixture = source / "synthetic.txt"
        fixture.write_text(fixture_text + "\n")
        status, added, _ = client.request("POST", "/api/sources", {"root": str(source), "label": "Synthetic desktop acceptance"})
        require(status == 201, "source-create-failed")
        journey._run_scan(client, added["id"], expected_rule, 90, checks, details)
        status, saved, _ = client.request("POST", "/api/vault/entries", {"title": "Synthetic desktop credential", "secret": secret})
        require(status == 201 and "secret" not in saved, "credential-save-failed")
        entry = quote(saved["id"], safe="")
        require(client.request("PATCH", f"/api/vault/entries/{entry}", {"title": "Renamed synthetic credential"})[0] == 200, "metadata-edit-failed")
        status, revealed, _ = client.request("POST", f"/api/vault/entries/{entry}/reveal", {}, deliberate_reveal=True)
        require(status == 200 and revealed.get("secret") == secret, "metadata-edit-erased-secret")
        del revealed
        status, backup, _ = client.request("POST", "/api/vault/backup", {"passphrase": backup_phrase}, protected_backup=True)
        require(status == 200, "backup-failed")
        journey._check_backup_ciphertext(base64.b64decode(backup["backup_base64"], validate=True), tuple(sensitive))
        child.command("lock-credentials")
        require(client.request("GET", "/api/vault/entries")[0] >= 400, "control-lock-not-enforced")
        require(client.request("GET", "/api/findings")[0] == 200, "credential-lock-locked-scan-store")
        require(client.request("POST", "/api/vault/restore", {"backup": backup["backup_base64"], "backup_passphrase": backup_phrase,
                                                              "new_passphrase": vault_phrase}, protected_backup=True)[0] >= 400,
                "restore-replaced-without-explicit-flag")
        require(client.request("POST", "/api/vault/restore", {"backup": backup["backup_base64"], "backup_passphrase": backup_phrase,
                                                              "new_passphrase": vault_phrase, "replace": True}, protected_backup=True)[0] == 200,
                "explicit-restore-failed")
        checks["explicit_vault_save_reveal_edit_lock_backup_restore"] = True
        plugin = next(resources.glob("backend/LeakGuard/wheelhouse/leakguard_firm_example-*.whl"))
        status, installed, _ = client.request("POST", "/api/plugins/install", {"filename": plugin.name,
                                               "wheel": base64.b64encode(plugin.read_bytes()).decode(), "reviewed": True})
        require(status == 201 or status == 200, "offline-plugin-install-failed")
        require(not installed.get("profiles"), "plugin-enabled-during-install")
        plugin_id = installed["id"]
        checked = client.request("POST", "/api/plugins/conformance", {"id": plugin_id})
        require(checked[0] == 200 and checked[1].get("passed") is True, "plugin-conformance-failed")
        require(client.request("POST", "/api/plugins/enable", {"id": plugin_id, "profile": "firm"})[0] == 200, "explicit-plugin-enable-failed")
        checks["offline_plugin_private_runtime_and_explicit_profile_enable"] = True
        repository = work / "repository"
        repository.mkdir(mode=0o700)
        git_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run(["git", "-c", "init.templateDir=", "init", "-q", str(repository)], env=git_env, check=True)
        require(client.request("POST", "/api/hooks/install", {"repository": str(repository), "profile": "credentials"})[0] == 200, "guard-install-failed")
        hook = repository / ".git/hooks/pre-commit"
        require(str(python).encode() in hook.read_bytes(), "guard-private-runtime-path-missing")
        status, hooks, _ = client.request("GET", "/api/hooks/status?" + urlencode({"repository": str(repository)}))
        require(status == 200 and hooks.get("managed"), "guard-status-failed")
        require(client.request("POST", "/api/hooks/uninstall", {"repository": str(repository)})[0] == 200 and not hook.exists(), "guard-uninstall-failed")
        checks["disposable_git_guards_use_stable_runtime"] = True
        all_bodies.extend(client.bodies)
        require(child.stop(), "owned-backend-stop-failed")
        checks["owned_safe_shutdown"] = True
        reused, stages = prepare(resources, profile)
        require(reused == runtime and not any(line.get("stage") == "installing-backend" for line in stages), "runtime-reinstalled-on-reuse")
        marker = profile / "profile/desktop-runtime.json"
        original_marker = marker.read_bytes()
        try:
            changed = json.loads(original_marker)
            changed["runtimeId"] = "0" * 64
            marker.write_text(json.dumps(changed))
            before_state = {path.relative_to(state).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in state.rglob("*") if path.is_file()}
            prepare(resources, profile, expected_error="runtime-migration-required")
            require(before_state == {path.relative_to(state).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                     for path in state.rglob("*") if path.is_file()}, "mismatch-altered-state")
        finally:
            marker.write_bytes(original_marker)
        checks["same_identity_reuses_plugins_mismatch_preserves_state"] = True
        restarted = DesktopChild(python, state, config, profile)
        children.append(restarted)
        second_ready = restarted.next()
        second = journey.BuddyClient(second_ready["origin"], timeout=20)
        second_token = restarted.command("bootstrap")["token"]
        sensitive.append(second_token.encode())
        second.exchange(second_token)
        status = second.request("GET", "/api/status")[1]
        require(status["observations"]["created"] and not status["observations"]["unlocked"]
                and status["vault"]["created"] and not status["vault"]["unlocked"], "stores-not-retained-locked-after-restart")
        plugins = second.request("GET", "/api/plugins")[1]["plugins"]
        require(any(item["id"] == plugin_id and "firm" in item["profiles"] for item in plugins), "plugin-not-retained-on-reuse")
        all_bodies.extend(second.bodies)
        if args.browser_inputs:
            browser_token = restarted.command("bootstrap")["token"]
            sensitive.append(browser_token.encode())
            browser = subprocess.run(["node", str(ROOT / "tools/check_desktop_browser.mjs")],
                                     input=json.dumps({"browserInputs": str(args.browser_inputs.resolve()),
                                                       "origin": second_ready["origin"], "token": browser_token,
                                                       "observationPhrase": observation_phrase,
                                                       "screenshot": str(work / "findings.png")}).encode(),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            require(browser.returncode == 0, "production-browser-check-failed")
            details["browser"] = json.loads(browser.stdout)
            checks["production_browser_nonce_navigation_real_findings"] = details["browser"].get("passed") is True
        require(restarted.stop(), "restarted-backend-stop-failed")
        checks["encrypted_stores_and_plugins_retained_after_restart"] = True
        journey._artifact_review(state, b"\n".join(bytes(item.errors) for item in children), all_bodies, fixture, tuple(sensitive))
        checks["no_fixture_secrets_in_plaintext_state_stderr_or_unclassified_api"] = True
        require((resources / "desktop-manifest.json").read_bytes() == manifest_before, "bundle-manifest-mutated")
        # Full closure verification also catches Python bytecode written into the app bundle.
        prepare(resources, profile)
        checks["bundle_unchanged_after_runtime_and_api_journey"] = True
        receipt["passed"] = all(checks.values())
    except (CheckFailure, journey.JourneyFailure) as error:
        receipt["failure"] = str(error)
    except Exception as error:
        receipt["failure"] = "harness-" + type(error).__name__
    finally:
        for child in children:
            if child.process.poll() is None and not child.stop():
                safe_cleanup = False
        receipt["elapsedSeconds"] = round(time.monotonic() - started, 3)
        receipt["ownedProcessesStopped"] = safe_cleanup
        receipt["profileRetained"] = args.keep_profile or not safe_cleanup
        if safe_cleanup and not args.keep_profile:
            for name in ("desktop-profile", "source", "repository"):
                path = work / name
                if path.exists() and not path.is_symlink():
                    shutil.rmtree(path)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        if os.name != "nt":
            args.receipt.chmod(0o600)
        print(json.dumps({"passed": receipt["passed"], "receipt": str(args.receipt), "ownedProcessesStopped": safe_cleanup}))
    return 0 if receipt["passed"] and safe_cleanup else 1


if __name__ == "__main__":
    raise SystemExit(main())
