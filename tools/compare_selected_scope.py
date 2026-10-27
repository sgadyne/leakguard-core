#!/usr/bin/env python3
"""Compare two installed CLIs on an explicitly selected, immutable file list.

Input manifest is JSON {"files": [{"path":"/absolute/file", "size":123,
"sha256":"..."}, ...]}. Only sanitized,
value-free metadata is emitted; scanner stdout/stderr and state stay in a
private temporary directory and are removed. Never use with unapproved roots.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_FILES = 256
MAX_BYTES = 8_000_000
MAX_REPORT = 8_000_000
RULE = re.compile(r'[a-z][a-z0-9-]{0,79}\Z')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot(files):
    result = []
    total = 0
    for path in files:
        # Resolve every component; do not follow symlinks into unselected scope.
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('scope-invalid')
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('scope-invalid')
        total += before.st_size
        if total > MAX_BYTES:
            raise ValueError('scope-limit')
        fingerprint = digest(path)
        after = path.stat(follow_symlinks=False)
        sig = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if sig(before) != sig(after):
            raise ValueError('scope-changed')
        result.append((sig(after), fingerprint))
    return result


def run(cli, config, files, temp, label, budget):
    output = temp / (label + '.json')
    errors = temp / (label + '.stderr')
    state = temp / (label + '-state')
    state.mkdir(mode=0o700)
    args = [str(cli), 'scan', '--config', str(config), '--state-dir', str(state),
            '--format', 'json', '--no-cache', '--budget-seconds', str(budget),
            '--max-files', str(len(files)), '--', *(str(p) for p in files)]
    with output.open('xb') as out, errors.open('xb') as err:
        os.chmod(output, 0o600)
        os.chmod(errors, 0o600)
        process = subprocess.run(args, stdout=out, stderr=err, timeout=budget + 30, check=False)
    if process.returncode != 0 or output.stat().st_size > MAX_REPORT:
        raise ValueError('scan-failed-or-report-limit')
    report = json.loads(output.read_text(encoding='utf-8'))
    counts, coverage, results = report['counts'], report['coverage'], report['results']
    if (coverage['enumeration_complete'] is not True or coverage['required_complete'] is not True
            or counts['scanned'] != len(files) or any(counts[k] for k in ('reused', 'skipped', 'errors', 'interrupted', 'omitted_results', 'incomplete_results'))
            or len(results) != len(files)):
        raise ValueError('scan-incomplete')
    indices = {str(path): i for i, path in enumerate(files)}
    observations = []
    seen = set()
    for result in results:
        path = result['source']['path']
        if path not in indices or path in seen or result['outcome'] != 'scanned':
            raise ValueError('scope-mismatch')
        seen.add(path)
        for item in result['findings']:
            rule, detector, severity = item['rule'], item['detector_id'], item['severity']
            part = item['part_id']
            start, end = item['start_line'], item['end_line']
            if (not isinstance(rule, str) or not RULE.fullmatch(rule) or not isinstance(detector, str)
                    or not RULE.fullmatch(detector) or severity not in ('block', 'review', 'info')
                    or type(part) is not str or len(part) > 4096
                    or type(start) is not int or type(end) is not int or not 1 <= start <= end):
                raise ValueError('report-invalid')
            part_id = hashlib.sha256(part.encode('utf-8')).hexdigest()
            observations.append((indices[path], part_id, start, end, rule, detector, severity))
    return Counter(observations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True, help='Explicit selected repository root')
    parser.add_argument('--expected-count', type=int, required=True)
    for label in ('baseline', 'candidate'):
        parser.add_argument('--' + label, type=Path, required=True, help='Installed leakguard executable')
        parser.add_argument('--' + label + '-config', type=Path, required=True)
    parser.add_argument('--budget-seconds', type=int, default=300)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        items = manifest['files']
        root = args.root
        if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError('scope-invalid')
        if type(items) is not list or not 1 <= len(items) <= MAX_FILES or len(items) != args.expected_count:
            raise ValueError('manifest-invalid')
        if any(type(x) is not dict or set(x) != {'path', 'size', 'sha256'} or
               type(x['path']) is not str or type(x['size']) is not int or x['size'] < 0 or
               type(x['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', x['sha256']) for x in items):
            raise ValueError('manifest-invalid')
        files = [Path(x['path']) for x in items]
        if (len(set(files)) != len(files) or any(not p.is_relative_to(root) for p in files)
                or not 1 <= args.budget_seconds <= 300):
            raise ValueError('manifest-invalid')
        def git_status():
            return subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain=v1', '-z', '--untracked-files=all'],
                                           stderr=subprocess.DEVNULL, timeout=30)
        initial_status = git_status()
        before = snapshot(files)
        if any(stat_info[2] != item['size'] or fingerprint != item['sha256']
               for (stat_info, fingerprint), item in zip(before, items)):
            raise ValueError('manifest-mismatch')
        identity = {label: {'executable_sha256': digest(getattr(args, label)),
                            'config_sha256': digest(getattr(args, label + '_config'))}
                    for label in ('baseline', 'candidate')}
        with tempfile.TemporaryDirectory(prefix='leakguard-compare-') as directory:
            temp = Path(directory)
            os.chmod(temp, 0o700)
            old = run(args.baseline, args.baseline_config, files, temp, 'baseline', args.budget_seconds)
            if snapshot(files) != before:
                raise ValueError('scope-changed')
            if git_status() != initial_status:
                raise ValueError('repository-changed')
            new = run(args.candidate, args.candidate_config, files, temp, 'candidate', args.budget_seconds)
            if snapshot(files) != before:
                raise ValueError('scope-changed')
            if git_status() != initial_status:
                raise ValueError('repository-changed')
            for label in ('baseline', 'candidate'):
                if (digest(getattr(args, label)) != identity[label]['executable_sha256'] or
                        digest(getattr(args, label + '_config')) != identity[label]['config_sha256']):
                    raise ValueError('runtime-changed')
        def rows(counter):
            return [{'file_index': i, 'part_id_sha256': part, 'start_line': first, 'end_line': last, 'rule': rule,
                     'detector': detector, 'severity': severity, 'count': count}
                    for (i, part, first, last, rule, detector, severity), count in sorted(counter.items())]
        print(json.dumps({'schema_version': 1, 'file_count': len(files), 'identity': identity,
                          'baseline_count': sum(old.values()), 'candidate_count': sum(new.values()),
                          'removed': rows(old - new), 'added': rows(new - old),
                          'scope_unchanged': True, 'repository_status_unchanged': True, 'complete': True}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError):
        # Do not echo exceptions: they may include source paths or child output.
        print('comparison-failed; inspect locally without publishing raw scanner output', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
