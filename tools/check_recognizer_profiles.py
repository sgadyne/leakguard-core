#!/usr/bin/env python3
"""Installed CLI, Git guard and encrypted host gate using disposable JWE keys.

This is an integration gate, not a quality corpus or validity/authentication
check. Run with installed wheels outside the checkout and retain the receipt.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import threading
import time


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _jwe(direct=False):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    # Leading JSON whitespace deliberately avoids relying on an eyJ prefix.
    protected = _b64((' {"enc":"A256GCM","alg":"' + ('dir' if direct else 'A256KW') + '"}').encode())
    cek, iv = os.urandom(32), os.urandom(12)
    key = b'' if direct else aes_key_wrap(os.urandom(32), cek)
    encrypted = AESGCM(cek).encrypt(iv, b'Synthetic disposable integration payload', protected.encode('ascii'))
    return '.'.join((protected, _b64(key), _b64(iv), _b64(encrypted[:-16]), _b64(encrypted[-16:])))


def _jws():
    protected = _b64(b' {"kid":"synthetic","alg":"HS256"}')
    payload = _b64(b'{"sub":"synthetic"}')
    signed = protected + '.' + payload
    return signed + '.' + _b64(hmac.digest(os.urandom(32), signed.encode('ascii'), 'sha256'))


def _unverified():
    protected = _b64(b'{"alg":"Future-Algorithm","enc":"A256GCM"}')
    return '.'.join((protected, _b64(os.urandom(40)), _b64(os.urandom(12)),
                     _b64(os.urandom(32)), _b64(os.urandom(16))))


def _firm_name_collision_gate():
    """A selected firm recognizer may share an unselected builtin's name."""
    import types
    from presidio_analyzer import EntityRecognizer, RecognizerResult
    from presidio_analyzer.predefined_recognizers import CreditCardRecognizer
    from presidio_detector.plugin import PresidioDetector

    class FirmCollisionRecognizer(EntityRecognizer):
        def __init__(self):
            super().__init__(supported_entities=['FIRM_COLLISION_ID'],
                             name=CreditCardRecognizer().name, supported_language='en')

        def analyze(self, text, entities, nlp_artifacts=None):
            return [RecognizerResult('FIRM_COLLISION_ID', 0, len('SyntheticFixture'), 0.9)]

    module_name = '_leakguard_profile_collision_fixture'
    assert module_name not in sys.modules
    module = types.ModuleType(module_name)
    module.build = lambda options: [FirmCollisionRecognizer()]
    sys.modules[module_name] = module
    detector = None
    try:
        detector = PresidioDetector({
            'entities': ['EMAIL_ADDRESS', 'FIRM_COLLISION_ID'],
            'recognizer-modules': [module_name + ':build'],
        })
        findings = list(detector.detect('SyntheticFixture person@example.com', None))
        assert any(f.analysis.entity_type == 'FIRM_COLLISION_ID' and f.analysis.start == 0
                   and f.analysis.end == len('SyntheticFixture') for f in findings), 'firm-name-collision-removed-selected-recognizer'
        assert any(f.analysis.entity_type == 'EMAIL_ADDRESS' for f in findings), 'firm-name-collision-removed-selected-builtin'
        assert all(value not in repr(findings) for value in ('SyntheticFixture', 'person@example.com')), 'firm-name-collision-redaction'
        return {'selected_firm_recognizer_preserved': True, 'selected_builtin_preserved': True,
                'exact_firm_span': True, 'value_free': True}
    finally:
        if detector is not None:
            detector.close()
        sys.modules.pop(module_name, None)


def _run(argv, *, cwd, env, expected=0, private_values=(), input_text=None):
    result = subprocess.run([str(item) for item in argv], cwd=cwd, env=env,
                            input=input_text, text=True, capture_output=True, timeout=180)
    # Exceptions and receipts never include captured source bytes or stderr.
    assert result.returncode == expected, f'integration-command-status:{Path(argv[0]).name}:{result.returncode}:expected{expected}'
    assert all(value not in result.stdout + result.stderr for value in private_values), 'integration-command-redaction'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--core-only-python', type=Path,
                        help='Fresh core-only installed interpreter, for optional-dependency coverage checks')
    args = parser.parse_args()
    os.umask(0o077)
    owned = args.output_dir.resolve()
    owned.mkdir(parents=True, exist_ok=False)
    source_root = args.source_root.resolve()
    origins = {}
    for name in ('leakguard_core', 'credential_detector', 'presidio_detector', 'jose_recognizers', 'leakguard_host',
                 'leakguard_vault', 'firm_presidio_recognizer'):
        module = importlib.import_module(name)
        origin = Path(module.__file__).resolve()
        assert not origin.is_relative_to(source_root), 'source-import-in-installed-gate'
        origins[name] = str(origin)

    from leakguard_core import ScanConfig, ScanLimits, parse_report
    from leakguard_core.recognizer_profiles import PII_ENTITIES, PROFILES, compose
    from leakguard_core.hooks import install_repository
    from leakguard_host import HostService
    from leakguard_vault import EncryptedScanStore
    import psutil

    jwe_tokens = [_jwe(), _jwe(True)]
    jws_token, unverified_token = _jws(), _unverified()
    tokens = [*jwe_tokens, jws_token, unverified_token]
    fixture_root = owned / 'synthetic'
    fixture_root.mkdir()
    firm_identifier = 'FIRM-DEMO-A1B2C3D4'
    bank_number = '998877665'
    private_values = [*tokens, firm_identifier, bank_number]
    text = ('\u03bb synthetic ' + firm_identifier + '\r\n' + '\r\n'.join(tokens)
            + '\r\nbank account routing number: ' + bank_number)
    fixture = fixture_root / 'sample.txt'
    fixture.write_bytes(text.encode())
    initial_digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    env = {key: value for key, value in os.environ.items()
           if key not in {'PYTHONPATH', 'LEAKGUARD_CONFIG', 'LEAKGUARD_STATE_DIR', 'LEAKGUARD_GITLEAKS'}
           and not key.startswith('GIT_')}
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull})
    receipts = []
    memory = {'peak_parent_rss_bytes': 0, 'peak_child_rss_bytes': 0,
              'peak_aggregate_child_rss_bytes': 0, 'sample_interval_seconds': 0.05}
    stop_sampling = threading.Event()
    def sample_memory():
        process = psutil.Process()
        while not stop_sampling.is_set():
            try:
                memory['peak_parent_rss_bytes'] = max(memory['peak_parent_rss_bytes'], process.memory_info().rss)
                children = []
                for child in process.children(recursive=True):
                    try:
                        children.append(child.memory_info().rss)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                memory['peak_child_rss_bytes'] = max(memory['peak_child_rss_bytes'], max(children, default=0))
                memory['peak_aggregate_child_rss_bytes'] = max(memory['peak_aggregate_child_rss_bytes'], sum(children))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            stop_sampling.wait(memory['sample_interval_seconds'])
    sampler = threading.Thread(target=sample_memory, daemon=True)
    sampler.start()
    started = time.monotonic()
    for profile in PROFILES:
        lane = owned / profile
        lane.mkdir()
        base = {'gitleaks_executable': str(args.gitleaks.resolve()),
                'worker_policy': 'supervised-alpha', 'scan_workers': 1,
                'worker_memory_bytes': 1024 * 1024 * 1024}
        if profile == 'firm':
            base['plugins'] = [{'module': 'presidio_detector.plugin', 'options': {
                'entities': [*PII_ENTITIES, 'FIRM_ACCOUNT_ID'],
                'recognizer-modules': ['firm_presidio_recognizer.plugin:build_recognizers'],
                'recognizer-options': '{"firm_presidio_recognizer.plugin:build_recognizers":{"prefix":"FIRM-DEMO"}}'}}]
        expected_config = compose(profile, base)
        base_path = lane / 'base-profile.json'
        base_path.write_text(json.dumps(base))
        path = lane / 'profile.json'
        composer = Path(sysconfig.get_path('scripts')) / ('leakguard-recognizer-profile' + ('.exe' if os.name == 'nt' else ''))
        _run([composer, '--profile', profile, '--base-config', base_path, '--output', path],
             cwd=owned, env=env, private_values=private_values)
        config = json.loads(path.read_text())
        assert config == expected_config, 'installed-composer-config'
        command = [sys.executable, '-m', 'leakguard_core', 'scan', fixture,
                   '--config', path, '--state-dir', lane / 'cli-state', '--format', 'json', '--no-cache']
        result = _run(command, cwd=owned, env=env, private_values=private_values)
        report = parse_report(result.stdout)
        assert report.coverage.required_complete, 'native-cli-incomplete'
        jose = [finding for row in report.results for finding in row.findings
                if finding.analysis and finding.analysis.entity_type == 'JOSE_COMPACT_JWE']
        assert len(jose) == 2, 'native-cli-jwe-coverage'
        assert all(finding.severity.value == 'review' for finding in jose), 'generic-jwe-policy'
        if profile == 'firm':
            assert any(f.analysis and f.analysis.entity_type == 'FIRM_ACCOUNT_ID'
                       for row in report.results for f in row.findings), 'firm-factory-seam'
        for token in jwe_tokens:
            assert any(f.analysis.start == text.index(token) and f.analysis.end == text.index(token) + len(token)
                       for f in jose), 'native-cli-original-offsets'
        for token, entity in ((jws_token, 'JOSE_COMPACT_JWS_CANDIDATE'),
                              (unverified_token, 'JOSE_COMPACT_UNVERIFIED')):
            assert any(f.analysis and f.analysis.entity_type == entity and f.analysis.start == text.index(token)
                       and f.analysis.end == text.index(token) + len(token) and f.severity.value == 'review'
                       for row in report.results for f in row.findings), 'native-cli-other-jose-coverage'
        banks = [f for row in report.results for f in row.findings
                 if f.analysis and f.analysis.entity_type == 'US_BANK_NUMBER']
        assert bool(banks) == (profile != 'credentials'), 'native-cli-selected-financial-coverage'
        if banks:
            assert any(f.analysis.start == text.index(bank_number) and f.analysis.end == text.index(bank_number) + len(bank_number)
                       for f in banks), 'native-cli-bank-offsets'

        # Real encrypted host orchestration, using the same explicit config.
        store_path = lane / 'observations.lgo'
        store = EncryptedScanStore.create(store_path, 'Disposable synthetic host passphrase 2026!', config=config)
        host = HostService(config=ScanConfig.from_mapping(config), scan_store=store,
                           limits=ScanLimits(60, 10, detector_timeout_seconds=45,
                                             worker_memory_bytes=1024 * 1024 * 1024))
        try:
            source = host.add_source(fixture_root)
            job = host.submit(source['id'])
            for _ in range(5):
                host.tick()
                if host.job(job['id'])['state'] in {'completed', 'failed'}:
                    break
            assert host.job(job['id'])['state'] == 'completed', 'native-host-incomplete'
            wire = store.latest_report().to_json()
            assert all(value not in wire for value in private_values), 'native-host-redaction'
            stored = store.query_findings()
            assert sum(bool(f.get('analysis') and f['analysis']['entity_type'] == 'JOSE_COMPACT_JWE') for f in stored) == 2, 'native-host-jwe-coverage'
            stored_entities = {f['analysis']['entity_type'] for f in stored if f.get('analysis')}
            assert {'JOSE_COMPACT_JWS_CANDIDATE', 'JOSE_COMPACT_UNVERIFIED'} <= stored_entities, 'native-host-other-jose-coverage'
            assert ('US_BANK_NUMBER' in stored_entities) == (profile != 'credentials'), 'native-host-selected-financial-coverage'
        finally:
            host.stop()
            store.close()
        assert all(token.encode() not in store_path.read_bytes() for token in tokens), 'encrypted-store-redaction'

        # Actual local Git operations exercise installed pre-commit/pre-push.
        repo, remote = lane / 'repo', lane / 'remote.git'
        repo.mkdir()
        def git(*argv, expected=0):
            return _run(['git', *argv], cwd=repo, env=env, expected=expected, private_values=private_values)
        git('init', '-q')
        git('config', 'user.name', 'Synthetic Integration')
        git('config', 'user.email', 'synthetic@example.invalid')
        git('init', '--bare', '-q', remote)
        git('remote', 'add', 'origin', remote)
        install_repository(repo, config_path=path, state_dir=lane / 'hook-state')
        (repo / 'review.txt').write_text(tokens[0] + '\n')
        git('add', 'review.txt')
        git('commit', '-qm', 'Synthetic review finding')
        git('push', '-q', 'origin', 'HEAD:refs/heads/review')
        # An explicit operator block policy is separate from structural score.
        blocked = json.loads(json.dumps(config))
        blocked['plugins'][0]['options']['block-entities'] = ['JOSE_COMPACT_JWE']
        path.write_text(json.dumps(blocked))
        (repo / 'blocked.txt').write_text(tokens[1] + '\n')
        git('add', 'blocked.txt')
        git('commit', '-qm', 'Must be blocked', expected=1)
        git('push', '-q', 'origin', 'HEAD:refs/heads/block-policy', expected=1)

        # Enabled-but-unavailable factory must not yield a successful clean scan.
        missing = json.loads(json.dumps(config))
        missing['plugins'][0]['options']['recognizer-modules'] = ['unavailable_jose_factory.plugin:build_recognizers']
        path.write_text(json.dumps(missing))
        _run(command, cwd=owned, env=env, expected=2, private_values=private_values)
        git('commit', '-qm', 'Missing required recognizer', expected=1)
        receipts.append({'profile': profile, 'cli_exact_jwe_spans': 2, 'cli_redacted_roundtrip': True,
                         'installed_composer_command': True,
                         'cli_exact_jws_spans': 1, 'cli_exact_unverified_spans': 1,
                         'financial_preset_active': profile != 'credentials',
                         'encrypted_host_jwe_spans': 2, 'default_review_commit_and_push_allowed': True,
                         'explicit_block_commit_and_push_rejected': True, 'missing_enabled_factory_failed_closed': True})

    firm_name_collision = _firm_name_collision_gate()
    core_only = {'checked': False}
    if args.core_only_python:
        # Preserve the venv path instead of following its executable symlink
        # to the base interpreter and losing the isolated environment.
        python = args.core_only_python.absolute()
        probe = _run([python, '-c', 'import importlib.util,json;print(json.dumps({n:importlib.util.find_spec(n) is not None for n in ("presidio_detector","jose_recognizers")}))'],
                     cwd=owned, env=env)
        assert json.loads(probe.stdout) == {'presidio_detector': False, 'jose_recognizers': False}, 'core-only-runtime-has-native-packages'
        plain = {'gitleaks_executable': str(args.gitleaks.resolve()), 'worker_policy': 'supervised-alpha'}
        path = owned / 'core-only.json'
        path.write_text(json.dumps(plain))
        command = [python, '-m', 'leakguard_core', 'scan', fixture, '--config', path,
                   '--state-dir', owned / 'core-only-state', '--format', 'json', '--no-cache']
        result = _run(command, cwd=owned, env=env, private_values=private_values)
        report = parse_report(result.stdout)
        assert report.coverage.required_complete, 'core-only-default-incomplete'
        assert not any(f.analysis and f.analysis.entity_type.startswith('JOSE_') for row in report.results for f in row.findings), 'core-only-coverage-claim'
        path.write_text(json.dumps(compose('credentials', plain)))
        _run(command, cwd=owned, env=env, expected=2, private_values=private_values)
        core_only = {'checked': True, 'native_packages_present': False,
                     'general_jose_findings': 0, 'explicit_native_profile_failed_closed': True}

    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == initial_digest, 'source-mutated'
    stop_sampling.set()
    sampler.join(timeout=2)
    remaining = [child for child in psutil.Process().children(recursive=True)
                 if child.is_running() and child.status() != psutil.STATUS_ZOMBIE]
    assert not remaining, 'owned-descendants-remained'
    receipt = {'schema_version': 1, 'synthetic_only': True, 'profiles': receipts,
               'installed_origins': origins, 'seconds': time.monotonic() - started,
               'sampled_memory': memory,
               'core_only': core_only,
               'firm_name_collision': firm_name_collision,
               'owned_descendants_remaining': 0,
               'source_unchanged': True, 'authentication_attempts': 0,
               'policy_note': 'Generic JOSE review is observable but allows Git unless explicitly configured to block.'}
    (owned / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
