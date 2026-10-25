"""Reproduce the October 2026 review using only disposable synthetic content.

Run with PYTHONPATH=src and --gitleaks /path/to/gitleaks. The child receives an
empty config and private state. JSON describes behavior; --assert-fixed requires
the corrected behavior. --benchmark adds a 50-file cold and warm scan.
"""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile


def probe(root, benchmark):
    from leakguard_core import engine as guard, hooks
    from leakguard_core import models

    synthetic = 'SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG'
    target = root / 'sample.txt'
    target.write_text('client_secret = "' + synthetic + '"\n', encoding='utf-8')
    service = guard.ScanService({
        'gitleaks_executable': str(guard.EXE),
        'gitleaks_config': str(guard.RULES),
    }, state_dir=root / 'typed-state')
    try:
        limits = models.ScanLimits(45, 100)
        first_report = service.scan(
            [models.FileInput(target)], policy=models.ScanPolicy.inventory(),
            limits=limits, use_cache=True,
        )
        second_report = service.scan(
            [models.FileInput(target)], policy=models.ScanPolicy.inventory(),
            limits=limits, use_cache=True,
        )
        first = first_report.results[0]
        second = second_report.results[0]
    finally:
        service.close()
    result = {'cache': {
        'first_status': first.outcome.value, 'first_findings': len(first.findings),
        'second_status': second.outcome.value, 'second_findings': len(second.findings),
        'same_finding_ids': sorted(item.id for item in first.findings)
                             == sorted(item.id for item in second.findings),
    }}

    repo = root / 'repo'
    repo.mkdir()

    def git(*args, check=True):
        return subprocess.run(['git', *args], cwd=repo, capture_output=True,
                              check=check, timeout=60)

    git('-c', 'init.templateDir=', 'init', '-q')
    git('config', 'user.name', 'Synthetic Review')
    git('config', 'user.email', 'review@example.invalid')
    git('config', 'commit.gpgsign', 'false')
    git('config', 'core.hooksPath', '.git/hooks')
    (repo / 'seed.txt').write_text('seed\n', encoding='utf-8')
    git('add', 'seed.txt')
    git('commit', '--no-verify', '-qm', 'Synthetic seed')
    hooks.install_at(repo / '.git/hooks')
    hook = repo / '.git/hooks/pre-commit'
    executable = os.access(hook, os.X_OK)
    (repo / 'credential.txt').write_bytes(target.read_bytes())
    git('add', 'credential.txt')
    commit = git('commit', '-qm', 'Synthetic guard check', check=False)
    result['installed_hook'] = {
        'executable': executable, 'commit_exit_code': commit.returncode,
        'blocks_staged_synthetic': commit.returncode != 0 and b'LeakGuard blocked' in commit.stderr,
        'output_redacted': synthetic.encode() not in commit.stdout + commit.stderr,
    }
    git('reset', '--', 'credential.txt')
    document = repo / 'no-text.docx'
    with zipfile.ZipFile(document, 'w') as archive:
        archive.writestr('[Content_Types].xml', '<Types/>')
    git('add', 'no-text.docx')
    document_report = guard.ScanService({
        'gitleaks_executable': str(guard.EXE),
        'gitleaks_config': str(guard.RULES),
    }, state_dir=root / 'document-state')
    try:
        typed = document_report.scan_git(
            repo, request=models.GitRequest(models.GitRequestKind.INDEX),
            limits=models.ScanLimits(45, 100),
        )
    finally:
        document_report.close()
    process = subprocess.run([sys.executable, '-m', 'leakguard_core', 'hook', 'pre-commit'],
                             cwd=repo, capture_output=True, timeout=90)
    issues = sorted({issue.code.value for scan in typed.results for issue in scan.issues})
    result['git_no_text_document'] = {
        'outcome': typed.results[0].outcome.value if typed.results else 'missing-result',
        'issues': issues, 'decision': typed.decision.verdict.value,
        'hook_exit_code': process.returncode,
        'blocks_incomplete_scan': process.returncode != 0,
    }

    if benchmark:
        corpus = root / 'corpus'
        corpus.mkdir()
        for index in range(50):
            (corpus / f'clean-{index}.txt').write_text(
                'A short ordinary text file.\n' * 20, encoding='utf-8')
        timings = []
        for _ in range(2):
            started = time.perf_counter()
            with contextlib.redirect_stdout(io.StringIO()):
                report = guard.scan_paths([str(corpus)], 30, 100)
            timings.append({'seconds': round(time.perf_counter() - started, 4),
                            'counts': report['file_counts']})
        result['50_text_files'] = timings
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks')
    parser.add_argument('--assert-fixed', action='store_true')
    parser.add_argument('--benchmark', action='store_true')
    parser.add_argument('--worker-root', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_root:
        result = probe(Path(args.worker_root), args.benchmark)
        print(json.dumps(result, indent=2))
        fixed = (result['cache']['first_findings'] > 0
                 and result['cache']['second_findings'] > 0
                 and result['cache']['same_finding_ids']
                 and result['installed_hook']['executable']
                 and result['installed_hook']['blocks_staged_synthetic']
                 and result['installed_hook']['output_redacted']
                 and result['git_no_text_document']['decision'] in {'block', 'incomplete'}
                 and result['git_no_text_document']['blocks_incomplete_scan'])
        return 1 if args.assert_fixed and not fixed else 0

    selected = args.gitleaks or os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks')
    if not selected:
        parser.error('provide --gitleaks /path/to/a/separately-installed/gitleaks')
    executable = Path(selected).expanduser().resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='leakguard-review-') as folder:
        root = Path(folder)
        config = root / 'config.json'
        config.write_text('{}', encoding='utf-8')
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('GIT_')}
        source = Path(__file__).resolve().parents[1] / 'src'
        environment.update(LEAKGUARD_CONFIG=str(config), LEAKGUARD_STATE_DIR=str(root / 'state'),
            LEAKGUARD_GITLEAKS=str(executable), GIT_CONFIG_NOSYSTEM='1',
            GIT_CONFIG_GLOBAL=os.devnull, PYTHONPATH=str(source))
        command = [sys.executable, str(Path(__file__).resolve()), '--worker-root', str(root)]
        if args.assert_fixed:
            command.append('--assert-fixed')
        if args.benchmark:
            command.append('--benchmark')
        return subprocess.run(command, env=environment, timeout=180).returncode


if __name__ == '__main__':
    raise SystemExit(main())
