#!/usr/bin/env python3
"""Small installed-runtime gate using invented fixtures and redacted receipts."""
import argparse
import io
import json
import os
from pathlib import Path
import runpy
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks', type=Path, required=True)
    parser.add_argument('--tika-archive', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    from leakguard_core import engine, models as m, __version__, parse_report
    from leakguard_tika_extractor.plugin import TIKA_ARCHIVE_SHA512
    import psutil
    from pypdf import PdfWriter
    helpers = runpy.run_path(str(Path(__file__).resolve().parents[1] /
        'plugins/tika_extractor/tests/test_tika_integration.py'))
    fixtures = args.output_dir / 'synthetic'; fixtures.mkdir(exist_ok=True)
    positive = 'Synthetic account FIRM-DEMO-A1B2C3D4; email person@example.com'
    marker = 'SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG'
    (fixtures / 'positive.txt').write_text(positive + '\npassword = "' + marker + '"\n')
    (fixtures / 'negative.txt').write_text('Ordinary synthetic release notes. No account identifier.')
    (fixtures / 'positive.pdf').write_bytes(helpers['_pdf_with_text'](positive))
    (fixtures / 'positive.docx').write_bytes(helpers['_docx'](
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>' + positive + '</w:t></w:r></w:p></w:body></w:document>'))
    encrypted = PdfWriter(); encrypted.add_blank_page(width=72, height=72)
    encrypted.encrypt('synthetic-unopened-fixture-password')
    output = io.BytesIO(); encrypted.write(output)
    (fixtures / 'encrypted.pdf').write_bytes(output.getvalue())
    (fixtures / 'malformed.docx').write_bytes(helpers['_docx']('<w:document><broken>'))
    (fixtures / 'unsupported.bin').write_bytes(bytes(range(256)))
    config = {'gitleaks_executable': str(args.gitleaks.resolve()),
        'worker_policy': 'supervised-alpha', 'scan_workers': 1,
        'worker_memory_bytes': 1024 * 1024 * 1024,
        'detection_profile': 'sensitive',
        'plugins': [
            {'module': 'presidio_detector.plugin', 'options': {
                'entities': ['EMAIL_ADDRESS', 'FIRM_ACCOUNT_ID'], 'ner-mode': 'pattern-only',
                'recognizer-modules': ['firm_presidio_recognizer.plugin:build_recognizers']}},
            {'module': 'leakguard_tika_extractor.plugin', 'options': {
                'artifact-path': str(args.tika_archive.resolve()),
                'artifact-sha512': TIKA_ARCHIVE_SHA512, 'java-path': str(args.java.resolve())}}],
        'extractor_overrides': {suffix: 'tika-extractor' for suffix in ('.pdf', '.docx')}}
    limits = m.ScanLimits(90, 16, worker_memory_bytes=1024 * 1024 * 1024)
    selected = [fixtures / name for name in ('positive.txt', 'negative.txt', 'positive.pdf', 'positive.docx')]
    before = {p.pid for p in psutil.Process().children(recursive=True)}
    started = time.monotonic()
    service = engine.ScanService(config)
    init_seconds = time.monotonic() - started
    try:
        started = time.monotonic()
        cold = service.scan_paths(selected, policy=m.ScanPolicy.inventory(), limits=limits)
        cold_seconds = time.monotonic() - started
        if not cold.coverage.required_complete:
            (args.output_dir / 'incomplete-diagnostic.json').write_text(cold.to_json())
            print(json.dumps({'coverage': cold.coverage.required_complete,
                'run_issues': [i.code.value for i in cold.issues],
                'results': [{'coverage': r.coverage.value, 'outcome': r.outcome.value,
                             'issues': [i.code.value for i in r.issues]} for r in cold.results]}))
        assert cold.coverage.required_complete, 'positive-fixture-incomplete'
        assert len(cold.results) == 4
        assert any(f.rule == 'literal-password' for r in cold.results for f in r.findings)
        assert any(f.analysis and f.analysis.entity_type == 'FIRM_ACCOUNT_ID' for r in cold.results for f in r.findings)
        assert any(f.analysis and f.analysis.entity_type == 'EMAIL_ADDRESS' for r in cold.results for f in r.findings)
        negative = next(r for r in cold.results if Path(r.source.path).name == 'negative.txt')
        assert not negative.findings
        wire = cold.to_json()
        assert marker not in wire and 'person@example.com' not in wire and 'FIRM-DEMO-A1B2C3D4' not in wire
        assert 'PRIVATE SYNTHETIC METADATA' not in wire
        assert parse_report(wire) == cold
        started = time.monotonic()
        warm = service.scan_paths(selected, policy=m.ScanPolicy.inventory(), limits=limits)
        warm_seconds = time.monotonic() - started
        assert warm.coverage.required_complete
        assert [(r.content, [(f.rule, f.start_line, f.end_line, f.analysis) for f in r.findings]) for r in cold.results] == [(r.content, [(f.rule, f.start_line, f.end_line, f.analysis) for f in r.findings]) for r in warm.results]
        sessions = service.plugin_session_metrics()
        assert len(sessions) == 2 and all(row['starts'] == 1 for row in sessions)
        controls = service.scan_paths([fixtures / name for name in ('encrypted.pdf', 'malformed.docx', 'unsupported.bin')],
            policy=m.ScanPolicy.inventory(required_formats=('all',)), limits=limits, use_cache=False)
        assert not controls.coverage.required_complete
        issues = {issue.code.value for row in controls.results for issue in row.issues}
        assert {'encrypted', 'extract-failed', 'unsupported-format'} <= issues
        runtime_before = service._runtime
        # Plugin settings are part of observed runtime identity; semantic reuse
        # stays disabled independently of this explicit invalidation check.
        from leakguard_core import scan_policy
        changed = json.loads(json.dumps(config))
        changed['plugins'][0]['options']['score-threshold'] = '0.99'
        runtime_after, eligible = scan_policy.runtime_identity(changed, str(args.gitleaks.resolve()))
        assert runtime_before != runtime_after and not eligible
        receipt = {'schema_version': 1, 'core_version': __version__,
            'synthetic_only': True, 'init_seconds': init_seconds,
            'cold_seconds': cold_seconds, 'warm_seconds': warm_seconds,
            'positive_results': len(cold.results), 'positive_required_complete': True,
            'findings': sum(len(r.findings) for r in cold.results),
            'negative_findings': 0, 'redacted_roundtrip': True,
            'plugin_sessions': sessions, 'control_issue_codes': sorted(issues),
            'runtime_settings_invalidated': True, 'plugin_semantic_reuse_enabled': False,
            'ner_enabled': False, 'tika_locations': 'aggregate-body-1-relative-unicode-offsets',
            'java': str(args.java.resolve()), 'tika_sha512': TIKA_ARCHIVE_SHA512}
    finally:
        service.close()
    remaining = [p for p in psutil.Process().children(recursive=True) if p.pid not in before
                 and p.is_running() and p.status() != psutil.STATUS_ZOMBIE]
    assert not remaining, 'owned-descendants-remained'
    receipt['owned_descendants_remaining'] = 0
    (args.output_dir / 'integration-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
