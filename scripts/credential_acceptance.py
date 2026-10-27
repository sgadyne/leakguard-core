#!/usr/bin/env python3
"""Independent installed credential gate. Run through the heavy admission wrapper.

Use an independently created, non-editable wheel environment and an empty output
path outside the source tree. The receipt contains only fixed labels and hashes;
command output and synthetic source bytes are never copied to it.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def require(condition, code):
    if not condition:
        raise AssertionError(code)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--expected-sha', required=True)
    parser.add_argument('--gitleaks', required=True, type=Path)
    parser.add_argument('--sealed-fixture', required=True, type=Path)
    parser.add_argument('--sealed-sha256', required=True)
    parser.add_argument('--fixture-kind', choices=('sealed', 'development'), default='sealed')
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--wheel', action='append', default=[], type=Path)
    args = parser.parse_args()
    source, owned = args.source_root.resolve(strict=True), args.output_dir.absolute()
    args.sealed_fixture = args.sealed_fixture.resolve(strict=True)
    args.gitleaks = args.gitleaks.resolve(strict=True)
    args.wheel = [path.resolve(strict=True) for path in args.wheel]
    require(not owned.resolve().is_relative_to(source) and not owned.exists(), 'output-location')
    require(not Path(sys.prefix).resolve().is_relative_to(source), 'venv-location')
    os.umask(0o077)
    owned.mkdir(mode=0o700, parents=True)
    os.chdir(owned)
    env = {k: v for k, v in os.environ.items() if k not in {'PYTHONPATH', 'PYTHONHOME', 'LEAKGUARD_CONFIG', 'LEAKGUARD_STATE_DIR', 'LEAKGUARD_GITLEAKS'} and not k.startswith('GIT_')}
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                'LEAKGUARD_GITLEAKS': str(args.gitleaks.resolve(strict=True)), 'PYTHONNOUSERSITE': '1'})
    receipt = {'schema': 1, 'status': 'running', 'source_sha': args.expected_sha, 'gates': {},
               'commands': [], 'artifacts': [], 'limitations': [
                   'Synthetic Linux installed checks only; hosted CI and other platforms require separate evidence.',
                   'Sealed fixtures qualify stated representations only; they do not establish production accuracy.']}
    private = []
    def run(cmd, *, cwd=owned, expected=0, extra_env=None):
        command = [str(x) for x in cmd]
        receipt['commands'].append(command)
        proc = subprocess.run(command, cwd=cwd, env=extra_env or env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=240)
        output = proc.stdout + proc.stderr
        require(not any(v.encode() in output for v in private), 'command-privacy')
        require(proc.returncode == expected, 'command-exit-' + str(proc.returncode) + '-expected-' + str(expected))
        return proc
    def gate(name, function):
        start = time.monotonic()
        try:
            function()
            receipt['gates'][name] = {'status': 'passed', 'seconds': round(time.monotonic()-start, 2)}
        except Exception as exc:
            code = str(exc) if isinstance(exc, AssertionError) and str(exc).isascii() and len(str(exc)) < 100 else type(exc).__name__
            receipt['gates'][name] = {'status': 'failed', 'code': code, 'seconds': round(time.monotonic()-start, 2)}
    try:
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
        require(actual == args.expected_sha and len(actual) == 40, 'source-commit-mismatch')
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=source), 'source-dirty')
        require(sha(args.sealed_fixture) == args.sealed_sha256, 'sealed-hash-mismatch')
        require(args.wheel, 'wheel-evidence-missing')
        receipt['artifacts'] = [{'filename': p.name, 'sha256': sha(p)} for p in args.wheel]
        modules = ('leakguard_core', 'credential_detector', 'presidio_detector', 'jose_recognizers', 'leakguard_host', 'leakguard_vault', 'private_credential_pack')
        origins = {name: Path(importlib.import_module(name).__file__).resolve() for name in modules}
        require(all(not p.is_relative_to(source) and p.is_relative_to(Path(sys.prefix).resolve()) for p in origins.values()), 'installed-origin')
        receipt['installed_origins'] = {name: str(path) for name, path in origins.items()}
        receipt['gitleaks_sha256'] = sha(args.gitleaks)
        receipt['fixture_kind'] = args.fixture_kind
        receipt['fixture_sha256'] = args.sealed_sha256

        from leakguard_core import ScanConfig, ScanLimits, parse_report
        from leakguard_core.recognizer_profiles import compose, JOSE_ENTITIES, JOSE_FACTORY
        base = {'gitleaks_executable': str(args.gitleaks.resolve()), 'worker_policy': 'supervised-alpha' if sys.platform == 'darwin' else 'strict',
                'worker_memory_bytes': 1024 * 1024 * 1024, 'scan_workers': 1}
        config = compose('credentials', base)
        config_path = owned / 'profile.json'
        config_path.write_text(json.dumps(config))
        def composition():
            specs = config['plugins']
            require(sum(s['module'] == 'credential_detector.plugin' for s in specs) == 1, 'credential-plugin-missing')
            p = next(s for s in specs if s['module'] == 'presidio_detector.plugin')['options']
            require(JOSE_FACTORY in p['recognizer-modules'] and set(JOSE_ENTITIES) <= set(p['entities']), 'jose-profile-missing')
            require(config['gitleaks_executable'] == str(args.gitleaks.resolve()), 'gitleaks-profile-missing')
            opts = {'entities': ['FIRM_ACCOUNT_ID'], 'recognizer-modules': ['firm_presidio_recognizer.plugin:build_recognizers'],
                    'recognizer-options': '{"firm_presidio_recognizer.plugin:build_recognizers":{"prefix":"FIRM-DEMO"}}',
                    'score-threshold': '0.7', 'block-entities': ['FIRM_ACCOUNT_ID']}
            original = {'plugins': [{'module': 'presidio_detector.plugin', 'options': opts}]}
            serialized = json.dumps(original, sort_keys=True)
            firm = compose('firm', original)
            require(json.dumps(original, sort_keys=True) == serialized, 'firm-input-mutated')
            actual_opts = next(s for s in firm['plugins'] if s['module'] == 'presidio_detector.plugin')['options']
            require(all(actual_opts[k] == opts[k] for k in ('recognizer-options', 'score-threshold', 'block-entities')), 'firm-options-lost')
            require(opts['recognizer-modules'][0] in actual_opts['recognizer-modules'], 'firm-factory-lost')
            require(any(s['module'] == 'credential_detector.plugin' for s in firm['plugins']), 'firm-credential-missing')
        gate('effective-composition', composition)

        test_path = source / 'tests/credentials_acceptance/test_taxonomy.py'
        def taxonomy(fixture):
            e = dict(env, CREDENTIAL_ACCEPTANCE_FIXTURE=str(fixture))
            run([sys.executable, '-I', test_path], extra_env=e)
        gate('development-taxonomy', lambda: taxonomy(source / 'tests/credentials_acceptance/development.json'))
        if args.fixture_kind == 'sealed':
            gate('sealed-taxonomy', lambda: taxonomy(args.sealed_fixture))

        marker = 'lg-synthetic-acceptance-M7q6v9R4'
        private.append(marker)
        text = 'π\nAuthorization: Bearer ' + marker + '\n'
        fixture_dir = owned / 'input'; fixture_dir.mkdir()
        fixture = fixture_dir / 'sample.txt'; fixture.write_text(text)
        before = sha(fixture)
        cli = [sys.executable, '-I', '-m', 'leakguard_core', 'scan', fixture, '--config', config_path,
               '--state-dir', owned / 'cli-state', '--format', 'json', '--fail-on', 'block']
        def cli_check():
            result = run(cli, expected=1)
            report = parse_report(result.stdout.decode())
            require(report.coverage.required_complete, 'cli-incomplete')
            hits = [f for r in report.results for f in r.findings if f.rule == 'credential-http-bearer']
            require(any(f.severity.value == 'block' and f.analysis and f.analysis.start == text.index(marker)
                        and f.analysis.end == text.index(marker) + len(marker) and f.start_line == 2 for f in hits), 'cli-block-location')
            require(sha(fixture) == before, 'cli-input-changed')
            require(all(marker.encode() not in p.read_bytes() for p in (owned / 'cli-state').rglob('*') if p.is_file()), 'cli-store-value-leak')
        gate('installed-cli-block-redaction-location', cli_check)

        def jose_review():
            def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
            token = '.'.join((b64(b'{"alg":"HS256"}'), b64(b'{"sub":"synthetic"}'), b64(b'j' * 32)))
            private.append(token)
            path = owned / 'jose.txt'; path.write_text(token + '\n')
            command = [sys.executable, '-I', '-m', 'leakguard_core', 'scan', path, '--config', config_path,
                       '--state-dir', owned / 'jose-state', '--format', 'json', '--fail-on', 'block']
            report = parse_report(run(command).stdout.decode())
            hits = [f for row in report.results for f in row.findings if f.analysis and f.analysis.entity_type == 'JOSE_COMPACT_JWS_CANDIDATE']
            require(report.coverage.required_complete and any(f.severity.value == 'review' for f in hits), 'jose-review-missing')
            require(not report.counts.block_findings, 'jose-accidental-block')
        gate('installed-jose-review', jose_review)

        def git_check():
            repo, remote = owned / 'repo', owned / 'remote.git'; repo.mkdir()
            def git(*args, expected=0): return run(['git', *args], cwd=repo, expected=expected)
            git('init', '-q'); git('config', 'user.name', 'Synthetic Test'); git('config', 'user.email', 'test@example.invalid')
            git('init', '--bare', '-q', remote); git('remote', 'add', 'origin', remote)
            (repo / 'sample.txt').write_text('clean\n'); git('add', 'sample.txt'); git('commit', '-qm', 'seed')
            git('push', '-q', 'origin', 'HEAD:refs/heads/main')
            hook = Path(sys.executable).with_name('leakguard-install-hooks')
            run([hook, 'install', repo, '--config', config_path, '--state-dir', owned / 'git-state'])
            f = repo / 'sample.txt'; f.write_text(text); git('add', 'sample.txt')
            git('commit', '-qm', 'blocked synthetic', expected=1)
            require(f.read_text() == text, 'git-input-changed')
            git('commit', '-qm', 'intermediate synthetic', '--no-verify')
            f.write_text('clean after synthetic\n'); git('add', 'sample.txt'); git('commit', '-qm', 'remove synthetic', '--no-verify')
            git('push', '-q', 'origin', 'HEAD:refs/heads/main', expected=1)
            require(f.read_text() == 'clean after synthetic\n', 'git-post-input-changed')
        gate('actual-git-commit-and-push-guards', git_check)

        def missing_plugin():
            # A disposable venv only: remove the configured package from the
            # child import path and always restore it before any other test.
            package = origins['credential_detector'].parent
            require(package.is_relative_to(Path(sys.prefix).resolve()), 'plugin-outside-venv')
            hidden = package.with_name(package.name + '-acceptance-hidden')
            require(not hidden.exists(), 'plugin-hide-conflict')
            package.rename(hidden)
            try:
                run(cli, expected=2)
            finally:
                hidden.rename(package)
        gate('missing-required-credential-fails-closed', missing_plugin)

        def nonreuse():
            from leakguard_core import engine, models
            service = engine.ScanService(config, state_dir=owned / 'cache-state')
            try:
                policy, limits = models.ScanPolicy.inventory(), models.ScanLimits(60, 1, worker_memory_bytes=1024*1024*1024)
                a = service.scan((models.FileInput(fixture),), policy=policy, limits=limits, use_cache=True)
                b = service.scan((models.FileInput(fixture),), policy=policy, limits=limits, use_cache=True)
                require(a.coverage.required_complete and b.coverage.required_complete, 'cache-scan-incomplete')
                require(a.results[0].outcome.value == 'scanned' and b.results[0].outcome.value == 'scanned', 'unknown-state-reused')
                require(not b.results[0].identity.cache_eligible, 'unknown-state-cache-eligible')
                require(any(f.rule == 'credential-http-bearer' for f in b.results[0].findings), 'cache-detector-missing')
            finally:
                service.close()
        gate('installed-unknown-state-nonreuse', nonreuse)

        def continuation():
            from leakguard_core import engine, models
            audit_dir = owned / 'audit-input'; audit_dir.mkdir()
            for name in ('a.txt', 'b.txt'):
                (audit_dir / name).write_text('clean synthetic\n')
            values = dict(config, audit_scopes={'acceptance': str(audit_dir)})
            service = engine.ScanService(values, state_dir=owned / 'audit-state')
            try:
                limits = models.ScanLimits(60, 1, worker_memory_bytes=1024*1024*1024)
                policy = models.ScanPolicy.inventory()
                identity1 = service.work_identity(policy=policy, limits=limits)
                identity2 = service.work_identity(policy=policy, limits=limits)
                require(identity1 != identity2, 'unknown-state-identity-stable')
                first = service.audit('acceptance', limits=limits, use_cache=True)
                second = service.audit('acceptance', limits=limits, use_cache=True)
                require(not first.coverage.required_complete and not second.coverage.required_complete, 'unknown-state-continuation-completed')
                require(len(first.results) == 1 and len(second.results) == 1, 'continuation-no-executed-slice')
                require(first.results[0].source.path == second.results[0].source.path, 'unknown-state-continuation-advanced')
                require(all(r.outcome.value == 'scanned' for report in (first, second) for r in report.results), 'unknown-state-continuation-reused')
                complete = service.audit('acceptance', limits=models.ScanLimits(60, 10, worker_memory_bytes=1024*1024*1024), use_cache=True)
                require(complete.coverage.required_complete and len(complete.results) == 2, 'unknown-state-single-slice-incomplete')
            finally:
                service.close()
        gate('installed-unknown-state-continuation-disabled', continuation)

        def private_extension():
            import importlib.resources
            from leakguard_core import engine, models
            from private_credential_pack.plugin import MANIFEST
            require(MANIFEST.external_state == 'unknown', 'private-manifest-state')
            data = json.loads(importlib.resources.files('private_credential_pack.resources').joinpath('aliases.json').read_text())
            key = data['aliases'][0]['name']
            source = owned / 'private-input'; source.mkdir()
            marker2 = 'lgSyntheticPrivateAcceptanceN62r'
            private.append(marker2)
            file = source / 'a.txt'; file.write_text(key + ' = "' + marker2 + '"\n')
            values = dict(base, plugins=[{'module': 'private_credential_pack.plugin'}], audit_scopes={'private': str(source)})
            service = engine.ScanService(values, state_dir=owned / 'private-state')
            try:
                limits = models.ScanLimits(60, 1, worker_memory_bytes=1024*1024*1024)
                reports = [service.scan((models.FileInput(file),), policy=models.ScanPolicy.inventory(), limits=limits, use_cache=True) for _ in range(2)]
                require(all(r.coverage.required_complete and r.results[0].outcome.value == 'scanned' and not r.results[0].identity.cache_eligible for r in reports), 'private-state-reused')
                require(any(f.rule.startswith('credential-') and f.severity.value == 'block' for f in reports[-1].results[0].findings), 'private-alias-missing')
                require(marker2 not in reports[-1].to_json(), 'private-report-value-leak')
                (source / 'b.txt').write_text('clean synthetic\n')
                identity1 = service.work_identity(policy=models.ScanPolicy.inventory(), limits=limits)
                identity2 = service.work_identity(policy=models.ScanPolicy.inventory(), limits=limits)
                require(identity1 != identity2, 'private-state-identity-stable')
                first = service.audit('private', limits=limits, use_cache=True)
                second = service.audit('private', limits=limits, use_cache=True)
                require(not first.coverage.required_complete and not second.coverage.required_complete, 'private-continuation-completed')
                require(len(first.results) == 1 and len(second.results) == 1, 'private-continuation-no-executed-slice')
                require(first.results[0].source.path == second.results[0].source.path, 'private-continuation-advanced')
                complete = service.audit('private', limits=models.ScanLimits(60, 10, worker_memory_bytes=1024*1024*1024), use_cache=True)
                require(complete.coverage.required_complete and len(complete.results) == 2, 'private-single-slice-incomplete')
            finally:
                service.close()
            require(file.read_text() == key + ' = "' + marker2 + '"\n', 'private-input-changed')
            require(all(marker2.encode() not in p.read_bytes() for p in (owned / 'private-state').rglob('*') if p.is_file()), 'private-store-value-leak')
        gate('installed-private-extension-and-nonreuse', private_extension)

        def host_check():
            from leakguard_host import HostService
            from leakguard_vault import EncryptedScanStore
            path = owned / 'host.lgo'
            store = EncryptedScanStore.create(path, 'Synthetic acceptance passphrase 2026!', config=config)
            host = HostService(config=ScanConfig.from_mapping(config), scan_store=store,
                               limits=ScanLimits(60, 10, detector_timeout_seconds=45, worker_memory_bytes=1024*1024*1024))
            try:
                src = host.add_source(fixture_dir); job = host.submit(src['id'])
                for _ in range(5):
                    host.tick()
                    if host.job(job['id'])['state'] in {'completed', 'failed', 'backoff'}: break
                require(host.job(job['id'])['state'] == 'completed', 'host-incomplete')
                rows = store.query_findings()
                require(any(r['rule'] == 'credential-http-bearer' and r['severity'] == 'block' for r in rows), 'host-finding-missing')
                require(marker not in json.dumps(rows) and marker not in store.latest_report().to_json(), 'host-value-leak')
            finally:
                host.stop(); store.close()
            require(marker.encode() not in path.read_bytes(), 'encrypted-store-value-leak')
            require(sha(fixture) == before, 'host-input-changed')
        gate('installed-host-action-and-store', host_check)
        receipt['status'] = 'passed' if all(g['status'] == 'passed' for g in receipt['gates'].values()) else 'failed'
    except Exception as exc:
        receipt['status'] = 'failed'
        receipt['error'] = str(exc) if isinstance(exc, AssertionError) and str(exc).isascii() and len(str(exc)) < 100 else type(exc).__name__
    finally:
        temp = owned / '.receipt.tmp'; temp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n'); os.replace(temp, owned / 'receipt.json')
        print(json.dumps({'status': receipt['status'], 'receipt': str(owned / 'receipt.json')}))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
