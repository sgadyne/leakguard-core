#!/usr/bin/env python3
"""Bounded synthetic-only cache comparison; invoke once for each source tree.

No source contents or matches enter the receipt. Use the same interpreter,
backend, source tree state and arguments for comparable before/after runs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
try:
    import resource
except ImportError:
    resource = None
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--backend', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--navigation-helper', type=Path)
    parser.add_argument('--files', type=int, default=48)
    parser.add_argument('--unique', type=int, default=12)
    parser.add_argument('--no-cache', action='store_true')
    args = parser.parse_args()
    if resource is None:
        parser.error('this developer resource benchmark requires a POSIX host')
    if not 1 <= args.unique <= args.files <= 128:
        parser.error('require 1 <= unique <= files <= 128')
    os.umask(0o077)
    sys.path.insert(0, str(args.source.resolve() / 'src'))
    from leakguard_core import engine, models as m, sources
    config = {'gitleaks_executable': str(args.backend.resolve()),
              'worker_policy': 'supervised-alpha', 'scan_workers': 2}
    if args.navigation_helper:
        config['navigation_helper'] = str(args.navigation_helper.resolve())
    with tempfile.TemporaryDirectory(prefix='leakguard-cache-bench-') as temporary:
        root = Path(temporary)
        for i in range(args.files):
            # Entirely invented, labeled synthetic specimens with fixed work.
            text = (f'# synthetic-only specimen {i % args.unique}\n'
                    'password = "SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG"\n'
                    + '# harmless padding\n' * 512)
            (root / f'case-{i:03}.txt').write_text(text, encoding='utf-8')
        manifest = [(p.name, hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_size)
                    for p in sorted(root.iterdir())]
        started = time.monotonic()
        with_service = engine.ScanService(config)
        try:
            report = with_service.scan_paths([root], policy=m.ScanPolicy.inventory(),
                    limits=m.ScanLimits(60, args.files), use_cache=not args.no_cache)
            cache = with_service.cache_metrics() if hasattr(with_service, 'cache_metrics') else None
            navigation = with_service.navigation_capabilities() if hasattr(with_service, 'navigation_capabilities') else {'backend': 'python-legacy'}
        finally:
            with_service.close()
        elapsed = time.monotonic() - started
        # One immutable 10 MiB byte snapshot, 100 identity accesses. Acquisition
        # is included, so this does not hide initial hashing in the new version.
        started_identity = time.monotonic()
        snapshot = sources.acquire_bytes(b'x' * (10 * 1024 * 1024), 'identity.bin', max_bytes=11 * 1024 * 1024)
        identities = [snapshot.content for _ in range(100)]
        identity_seconds = time.monotonic() - started_identity
        assert all(item == identities[0] for item in identities)
        signature = [(r.source.path.rsplit('/', 1)[-1], r.content.digest,
                      r.coverage.value, [(f.rule, f.start_line, f.end_line, f.severity.value) for f in r.findings],
                      [issue.code.value for issue in r.issues]) for r in report.results]
        signature.sort()
        usage = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        receipt = dict(schema_version=1, synthetic_only=True, files=args.files,
                       unique_contents=args.unique, source_bytes=sum(item[2] for item in manifest),
                       corpus_sha256=hashlib.sha256(json.dumps(manifest).encode()).hexdigest(),
                       result_sha256=hashlib.sha256(json.dumps(signature).encode()).hexdigest(),
                       required_complete=report.coverage.required_complete,
                       result_count=len(report.results), findings=sum(len(r.findings) for r in report.results),
                       elapsed_seconds=elapsed, identity_access_seconds=identity_seconds,
                       user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
                       child_user_seconds=children.ru_utime, child_system_seconds=children.ru_stime,
                       peak_self_rss_bytes=usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
                       peak_largest_child_rss_bytes=children.ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
                       cache=cache, navigation=navigation, use_cache=not args.no_cache)
        args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(receipt, stream, indent=2); stream.write('\n')
    return 0 if receipt['required_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
