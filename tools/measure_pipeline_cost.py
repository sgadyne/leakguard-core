#!/usr/bin/env python3
"""Measure a paired synthetic scan using the installed LeakGuard runtime.

Fixture JSON: {"synthetic_only": true, "files": [{"name": "a.txt", "text": "..."}]}
A file may instead contain bounded strict base64 in a "base64" field for binary formats.
Names are single path components; input is explicitly attested synthetic by its
creator. Files are staged into a private temporary directory in manifest order.
Use the same fixture, config, arguments, interpreter and backend for comparisons.
This command runs local scans only. It does not access SSH or a user's profile.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import asdict
from collections import Counter, defaultdict
from contextlib import ExitStack, contextmanager
import functools
import hashlib
import inspect
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import stat
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch


def digest(value):
    return hashlib.sha256(value).hexdigest()


def json_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())


def read_bounded(path, maximum):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('input is not a bounded regular file')
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('input exceeds limit')
        return data


def fixture(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    raw = read_bounded(path, 8_000_000)
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict or set(value) != {'synthetic_only', 'files'} or value['synthetic_only'] is not True:
        raise ValueError('fixture must attest synthetic_only and contain files')
    files = value['files']
    if type(files) is not list or not 1 <= len(files) <= 256:
        raise ValueError('fixture must contain 1 to 256 files')
    names = set()
    for entry in files:
        if type(entry) is not dict or set(entry) not in ({'name', 'text'}, {'name', 'base64'}):
            raise ValueError('invalid fixture entry')
        name = entry['name']
        content = entry.get('text', entry.get('base64'))
        if (type(name) is not str or not name or name in {'.', '..'} or '/' in name
                or '\\' in name or '\x00' in name or name in names or len(name) > 200
                or type(content) is not str):
            raise ValueError('invalid fixture file')
        try:
            payload = content.encode('utf-8') if 'text' in entry else base64.b64decode(content, validate=True)
        except (ValueError, UnicodeError, binascii.Error):
            raise ValueError('invalid fixture encoding') from None
        if len(payload) > 1_000_000:
            raise ValueError('invalid fixture file')
        entry['payload'] = payload
        names.add(name)
    return files, digest(raw)


class Meter:
    """Thread-local nesting; simultaneous worker spans deliberately overlap."""
    def __init__(self):
        self.local = threading.local()
        self.lock = threading.Lock()
        self.times = defaultdict(lambda: {'calls': 0, 'inclusive_ns': 0, 'exclusive_ns': 0})
        self.counts = Counter()
        self.acquisition_order = []

    def add(self, key, amount=1):
        with self.lock:
            self.counts[key] += amount

    @contextmanager
    def span(self, name):
        stack = getattr(self.local, 'stack', None)
        if stack is None:
            stack = self.local.stack = []
        frame = [time.perf_counter_ns(), 0]
        stack.append(frame)
        try:
            yield
        finally:
            elapsed = time.perf_counter_ns() - frame[0]
            stack.pop()
            if stack:
                stack[-1][1] += elapsed
            with self.lock:
                row = self.times[name]
                row['calls'] += 1
                row['inclusive_ns'] += elapsed
                row['exclusive_ns'] += max(0, elapsed - frame[1])

    def wrap(self, name, function, counter=None):
        if inspect.isgeneratorfunction(function):
            @functools.wraps(function)
            def generator_call(*args, **kwargs):
                if counter:
                    self.add(counter)
                return _TimedGenerator(function(*args, **kwargs), self, name)
            return generator_call
        @functools.wraps(function)
        def call(*args, **kwargs):
            if counter:
                self.add(counter)
            with self.span(name):
                return function(*args, **kwargs)
        return call

    def record_acquisition(self, path):
        with self.lock:
            self.acquisition_order.append(Path(path).name)

    def order_snapshot(self):
        with self.lock:
            return list(self.acquisition_order)

    def snapshot(self):
        with self.lock:
            return {'timings': {k: dict(v) for k, v in self.times.items()}, 'counts': dict(self.counts)}



class _TimedGenerator:
    """Time only generator execution, including explicit or abandoned close.

    Suspending at a yield ends the span, so consumer work is never charged to
    the producer and no timer remains on the thread-local stack between steps.
    """
    def __init__(self, generator, meter, name):
        self.generator, self.meter, self.name = generator, meter, name
    def __iter__(self):
        return self
    def __next__(self):
        with self.meter.span(self.name):
            return next(self.generator)
    def send(self, value):
        with self.meter.span(self.name):
            return self.generator.send(value)
    def throw(self, *args):
        with self.meter.span(self.name):
            return self.generator.throw(*args)
    def close(self):
        with self.meter.span(self.name):
            return self.generator.close()
    def __getattr__(self, name):
        return getattr(self.generator, name)
    def __del__(self):
        if self.generator.gi_frame is not None:
            self.close()

def difference(after, before):
    names = set(after['timings']) | set(before['timings'])
    fields = ('calls', 'inclusive_ns', 'exclusive_ns')
    return {'timings': {n: {k: after['timings'].get(n, {}).get(k, 0) - before['timings'].get(n, {}).get(k, 0) for k in fields} for n in sorted(names)},
            'counts': {k: after['counts'].get(k, 0) - before['counts'].get(k, 0) for k in sorted(set(after['counts']) | set(before['counts']))}}


class _ReadStream:
    def __init__(self, stream, meter):
        self.stream, self.meter = stream, meter
    def __enter__(self):
        self.stream.__enter__()
        return self
    def __exit__(self, *args):
        return self.stream.__exit__(*args)
    def __getattr__(self, name):
        return getattr(self.stream, name)
    def read(self, *args, **kwargs):
        result = self.stream.read(*args, **kwargs)
        self.meter.add('runtime_identity_stream_bytes_read', len(result))
        return result


class _OSProxy:
    def __init__(self, meter):
        self.meter = meter
    def __getattr__(self, name):
        return getattr(os, name)
    def fdopen(self, *args, **kwargs):
        return _ReadStream(os.fdopen(*args, **kwargs), self.meter)


class _TimedContext:
    def __init__(self, context, meter, label):
        self.context, self.meter, self.label = context, meter, label
    def __enter__(self):
        with self.meter.span(self.label):
            return self.context.__enter__()
    def __exit__(self, *args):
        with self.meter.span(self.label):
            return self.context.__exit__(*args)


class _SubprocessProxy:
    def __init__(self, meter, category):
        self.meter, self.category = meter, category
    def __getattr__(self, name):
        return getattr(subprocess, name)
    def Popen(self, *args, **kwargs):
        process = subprocess.Popen(*args, **kwargs)
        self.meter.add(self.category + '_process_starts')
        return process


@contextmanager
def instrumentation(meter):
    from leakguard_core import api, backends, engine, extraction, navigation, plugins, scan_policy, scan_store, sources, _session, _supervision
    # Patches are scoped to this isolated process and are restored even on error.
    # Functions that are imported at call time are patched at their definition.
    with ExitStack() as stack:
        def wrap(obj, name, label, counter=None):
            if hasattr(obj, name):
                original = getattr(obj, name)
                stack.enter_context(patch.object(obj, name, meter.wrap(label, original, counter)))
        # Classmethod descriptor must be preserved.
        original = api.Scanner.__dict__['open'].__func__
        stack.enter_context(patch.object(api.Scanner, 'open', classmethod(meter.wrap('scanner_open', original, 'scanner_open_calls'))))
        if hasattr(engine, '_PreparedRuntime'):
            wrap(engine._PreparedRuntime, '__init__', 'runtime_prepare', 'runtime_prepare_calls')
        wrap(scan_policy, 'runtime_identity', 'runtime_verification')
        original_admit = scan_policy._IdentityBudget.admit
        @functools.wraps(original_admit)
        def admit(budget, size):
            meter.add('runtime_identity_admitted_declared_bytes', size)
            return original_admit(budget, size)
        stack.enter_context(patch.object(scan_policy._IdentityBudget, 'admit', admit))
        stack.enter_context(patch.object(scan_policy, 'os', _OSProxy(meter)))
        wrap(api.Scanner, 'scan_paths', 'scan_paths')
        original_acquire = sources.acquire_file
        @functools.wraps(original_acquire)
        def acquire(path, *args, **kwargs):
            meter.record_acquisition(path)
            with meter.span('acquisition'):
                return original_acquire(path, *args, **kwargs)
        stack.enter_context(patch.object(sources, 'acquire_file', acquire))
        original_bounded = sources._bounded_file
        @functools.wraps(original_bounded)
        def bounded(*args, **kwargs):
            data = original_bounded(*args, **kwargs)
            meter.add('source_successful_bounded_read_bytes', len(data))
            return data
        stack.enter_context(patch.object(sources, '_bounded_file', bounded))
        wrap(sources, 'directory_signature', 'navigation_signature')
        for method in ('_python_listing', '_native_listing'):
            original_listing = getattr(navigation.Navigation, method)
            def listing(*args, _original=original_listing, **kwargs):
                return _TimedContext(_original(*args, **kwargs), meter, 'navigation_listing_open_close')
            stack.enter_context(patch.object(navigation.Navigation, method, listing))
        for cls in (navigation._PythonEntries, navigation._HelperEntries):
            wrap(cls, '__next__', 'navigation_next')
        wrap(navigation.Navigation, '_start_helper', 'navigation_helper_start', 'navigation_helper_start_attempts')
        wrap(extraction, 'extract', 'extraction')
        wrap(backends, 'detect', 'detection_native')
        wrap(plugins, 'detect', 'detection_plugin', 'plugin_detect_calls')
        for cls in (scan_store.MemoryScanStore, scan_store.SQLiteScanStore):
            wrap(cls, 'record_result', 'publication')
        # Imported aliases are intentional: both call sites must be wrapped.
        for module in (backends, plugins, extraction):
            wrap(module, 'run_worker', 'worker_run', 'worker_run_attempts')
        wrap(extraction, 'run_worker', 'parser_worker', 'parser_worker_attempts')
        wrap(_session.FramedWorker, '__init__', 'session_start', 'session_start_attempts')
        for module, category in ((_supervision, 'worker'), (_session, 'session'), (navigation, 'navigation_helper')):
            stack.enter_context(patch.object(module, 'subprocess', _SubprocessProxy(meter, category)))
        yield


def signature(report, root):
    rows = []
    for result in report.results:
        relative = str(Path(result.source.path).relative_to(root))
        findings = sorted((f.part_id, f.rule, f.detector_severity.value, f.severity.value,
                           f.start_line, f.end_line, f.classification.value, f.detector_id,
                           json_digest(asdict(f.analysis)) if f.analysis else '') for f in result.findings)
        issues = sorted((i.code.value, i.required, i.omission_id or '', i.part_id or '') for i in result.issues)
        rows.append((relative, result.coverage.value, result.content.digest if result.content else '',
                     result.identity.policy_id, result.identity.runtime_id, result.identity.context_id, findings, issues))
    def issue_source(i):
        if i.source is None:
            return ''
        try:
            return str(Path(i.source.path).relative_to(root))
        except ValueError:
            return '<outside-fixture>'
    issues = sorted((i.code.value, i.required, i.omission_id or '', i.part_id or '', issue_source(i)) for i in report.issues)
    value = {'results': sorted(rows), 'issues': issues,
             'omission_count': report.coverage.omission_count,
             'pending_files': report.coverage.pending_files,
             'pending_directories': report.coverage.pending_directories,
             'reason_codes': sorted(code.value for code in report.decision.reason_codes),
             'enumeration_complete': report.coverage.enumeration_complete,
             'required_complete': report.coverage.required_complete,
             'decision': report.decision.verdict.value}
    return json_digest(value), len(rows), sum(len(r.findings) for r in report.results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--backend', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--deadline', type=float, default=120)
    parser.add_argument('--max-file-bytes', type=int, default=1_000_000)
    parser.add_argument('--max-directory-entries', type=int, default=10000)
    parser.add_argument('--no-cache', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    files, fixture_digest = fixture(args.fixture)
    # Runtime must already be selected via the interpreter or PYTHONPATH.
    import leakguard_core
    from leakguard_core.api import ScanConfig, Scanner
    from leakguard_core.models import ScanLimits, ScanPolicy
    config = ScanConfig.from_file(args.config).to_mapping()
    config['gitleaks_executable'] = str(args.backend.resolve(strict=True))
    config = ScanConfig.from_mapping(config)
    limits = ScanLimits(args.deadline, len(files), max_file_bytes=args.max_file_bytes,
                        max_directory_entries=args.max_directory_entries)
    source_root = Path(leakguard_core.__file__).resolve().parent
    runtime_files = []
    for path in sorted(source_root.rglob('*.py')):
        if path.is_file() and not path.is_symlink():
            runtime_files.append((str(path.relative_to(source_root)), digest(read_bounded(path, 8_000_000))))
    versions = {}
    for package in ('pypdf', 'olefile', 'packaging', 'psutil', 'cachetools'):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    meter = Meter()
    receipt = {'schema_version': 1, 'synthetic_only': True,
        'identity': {'fixture_json_sha256': fixture_digest, 'config_raw_sha256': digest(read_bounded(args.config, 1_000_000)),
                     'effective_config_sha256': json_digest(config.to_mapping()), 'backend_sha256': digest(read_bounded(args.backend, 512 * 1024 * 1024)),
                     'runtime_python_tree_sha256': json_digest(runtime_files), 'measurement_tool_sha256': digest(read_bounded(Path(__file__), 1_000_000)),
                     'dependencies': versions, 'interpreter': platform.python_version(),
                     'platform': platform.platform(), 'limits': {'deadline_seconds': args.deadline, 'max_files': len(files),
                         'max_file_bytes': args.max_file_bytes, 'max_directory_entries': args.max_directory_entries}, 'use_cache': not args.no_cache},
        'fixture': {'file_count': len(files), 'declared_input_bytes': sum(len(f['payload']) for f in files),
                    'manifest_order_sha256': json_digest([(f['name'], digest(f['payload'])) for f in files])},
        'timing_accounting': 'Nanoseconds, summed per call. Exclusive subtracts directly nested instrumented spans on the same thread. Worker threads overlap each other and the main scan; sums are not a wall-time decomposition. Navigation measures listing open/close, next and directory signature calls, not all walk overhead. Source bounded-read bytes count returned data from successful reads, including source acquisition, proof/context reads and final validation, not failed or non-file reads. Generator timing calls count resume/close operations; plugin_detect_calls counts generator creation. Popen success counts report process starts; call attempts are separate. Runtime stream bytes count reads in scan_policy file identity only; admitted bytes are declared stat sizes, including rejected admissions. SSH RPC bytes are not measured.',
        'runs': []}
    with tempfile.TemporaryDirectory(prefix='leakguard-synthetic-cost-') as temporary:
        root = Path(temporary) / 'fixture'
        root.mkdir()
        for item in files:
            (root / item['name']).write_bytes(item['payload'])
        with instrumentation(meter):
            before = meter.snapshot()
            wall = time.perf_counter_ns()
            with Scanner.open(config=config) as scanner:
                opened = meter.snapshot()
                receipt['identity']['runtime_id'] = scanner._service._runtime
                for label in ('cold', 'warm'):
                    start = meter.snapshot()
                    cache_before = scanner.capabilities()
                    order_offset = len(meter.order_snapshot())
                    begin = time.perf_counter_ns()
                    report = scanner.scan_paths([root], policy=ScanPolicy.inventory(), limits=limits, use_cache=not args.no_cache)
                    elapsed = time.perf_counter_ns() - begin
                    cache_after = scanner.capabilities()
                    sig, count, findings = signature(report, root)
                    receipt['runs'].append({'label': label, 'wall_ns': elapsed,
                        'measurement': difference(meter.snapshot(), start),
                        'cache_before': cache_before.get('observation_cache'), 'cache_after': cache_after.get('observation_cache'),
                        'plugin_sessions_before': cache_before.get('plugin_sessions'), 'plugin_sessions_after': cache_after.get('plugin_sessions'),
                        'acquisition_order_sha256': json_digest(meter.order_snapshot()[order_offset:]),
                        'signature_sha256': sig, 'result_count': count, 'finding_count': findings,
                        'enumeration_complete': report.coverage.enumeration_complete, 'required_complete': report.coverage.required_complete,
                        'decision': report.decision.verdict.value})
                receipt['setup'] = difference(opened, before)
            receipt['total_wall_ns'] = time.perf_counter_ns() - wall
        receipt['all_fixture_files_reported'] = all(r['result_count'] == len(files) for r in receipt['runs'])
        receipt['acquisition_order_equal'] = receipt['runs'][0]['acquisition_order_sha256'] == receipt['runs'][1]['acquisition_order_sha256']
        receipt['signatures_equal'] = receipt['runs'][0]['signature_sha256'] == receipt['runs'][1]['signature_sha256']
        usage = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        scale = 1 if sys.platform == 'darwin' else 1024
        receipt['resources'] = {'self_peak_rss_bytes_process_lifetime': usage.ru_maxrss * scale,
                                'largest_child_peak_rss_bytes_process_lifetime': children.ru_maxrss * scale,
                                'self_user_seconds_process_lifetime': usage.ru_utime, 'self_system_seconds_process_lifetime': usage.ru_stime,
                                'children_user_seconds_process_lifetime': children.ru_utime, 'children_system_seconds_process_lifetime': children.ru_stime}
        with args.output.open('x', encoding='utf-8') as out:
            json.dump(receipt, out, indent=2, sort_keys=True)
            out.write('\n')
    return 0 if receipt['signatures_equal'] and receipt['acquisition_order_equal'] and receipt['all_fixture_files_reported'] and all(r['required_complete'] and r['enumeration_complete'] for r in receipt['runs']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
