"""Synthetic counterexamples for native filtering and line-only attribution.

No private data and no scanner startup. Optional direct Gitleaks checks use the
pinned binary from LEAKGUARD_GITLEAKS; the other tests use an in-process seam.
Current-behavior assertions document limitations, not desired policy.
"""
from __future__ import annotations

from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from leakguard_core import backends, engine, extraction, finding_details, models, sources


class NativeAttributionTests(unittest.TestCase):
    def test_native_parser_currently_discards_distinct_columns_including_unicode(self):
        # Synthetic Gitleaks rows for two separate matches on one Unicode line.
        text = 'é😀 password="synthetic-one" pwd="synthetic-two"'
        rows = [dict(RuleID='literal-password', StartLine=1, EndLine=1,
                     StartColumn=10, EndColumn=30),
                dict(RuleID='literal-password', StartLine=1, EndLine=1,
                     StartColumn=31, EndColumn=50)]
        worker = SimpleNamespace(returncode=1, stdout=json.dumps(rows).encode())
        prepared = backends.PreparedBackend('unused', Path('.'), Path('unused'))
        with patch.object(backends, 'run_worker', return_value=worker):
            observations = backends._detect(text, text.encode(), prepared, timeout=5,
                                             max_findings=10, cancel=None,
                                             worker_policy='strict')
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0], observations[1])
        self.assertEqual(observations[0], backends.BackendFinding('literal-password', 1, 1))
        self.assertFalse(hasattr(observations[0], 'start_column'))

    def scan_snapshot(self, text, rows, *, parts=None):
        service = engine.ScanService.__new__(engine.ScanService)
        service.config = {}
        service.binary = 'unused'
        service.rules = 'unused'
        service._plugins = []
        service._runtime = 'test-runtime'
        service._cache_eligible = False
        service._observation_scope = None
        snapshot = sources.acquire_bytes(text.encode(), 'fixture.txt', max_bytes=100_000)
        extraction_result = (extraction.ExtractionResult('text', 'extracted', tuple(parts))
                             if parts is not None else None)
        with patch.object(backends, 'detect', side_effect=rows):
            with patch.object(extraction, 'extract', return_value=extraction_result) if parts is not None else nullcontext():
                result, _, _ = service._scan_snapshot(snapshot, models.ScanPolicy.inventory(),
                    'test-policy', models.ScanLimits(10, 1), time.monotonic() + 10,
                    False, None)
        self.assertEqual(result.coverage, models.CoverageState.COMPLETE)
        return result.findings

    def test_same_line_same_rule_currently_collapses_but_other_lines_and_rules_survive(self):
        text = 'password="synthetic-one" pwd="synthetic-two"\npassword="synthetic-three"'
        rows = [[backends.BackendFinding('literal-password', 1, 1),
                 backends.BackendFinding('literal-password', 1, 1),
                 backends.BackendFinding('literal-client-secret', 1, 1),
                 backends.BackendFinding('literal-password', 2, 2)]]
        findings = self.scan_snapshot(text, rows)
        self.assertCountEqual([(x.rule, x.start_line) for x in findings],
                              [('literal-password', 1), ('literal-client-secret', 1),
                               ('literal-password', 2)])

    def test_part_boundaries_keep_equal_lines_distinct(self):
        # Simulate independently extracted parts, not a claim that text scans chunk.
        parts = [extraction.TextPart('text-1', 'password="synthetic-one"', 'text'),
                 extraction.TextPart('text-2', 'password="synthetic-two"', 'text')]
        rows = [[backends.BackendFinding('literal-password', 1, 1)],
                [backends.BackendFinding('literal-password', 1, 1)]]
        findings = self.scan_snapshot('synthetic', rows, parts=parts)
        self.assertCountEqual([x.part_id for x in findings], ['text-1', 'text-2'])

    def test_json_single_leaf_is_attributed_but_minified_multivalue_fails_closed(self):
        document = '{\n  "unicode": "é😀",\n  "api_key": "synthetic-token"\n}'
        self.assertEqual(finding_details.json_value_at_line(document, 3),
                         (['api_key'], 'synthetic-token'))
        mixed = '{"unicode":"é😀","api_key":"synthetic-one","pwd":"synthetic-two"}'
        self.assertIsNone(finding_details.json_value_at_line(mixed, 1))
        result = finding_details.describe({'path': 'fixture.json', 'line': 1,
            'rule': 'generic-api-key', 'severity': 'block'}, mixed.encode())
        self.assertEqual(result['severity'], 'block')
        self.assertNotIn('field', result)
        self.assertNotIn('classification', result)

    def test_invalid_or_split_json_cannot_grant_attribution(self):
        for text in ('{"api_key":"synthetic-one","api_key":"synthetic-two"}',
                     '{"api_key":"synthetic-', 'one"}'):
            with self.subTest(text=text):
                result = finding_details.describe({'path': 'fixture.json', 'line': 1,
                    'rule': 'generic-api-key', 'severity': 'block'}, text.encode())
                self.assertEqual(result['severity'], 'block')
                self.assertNotIn('field', result)


@unittest.skipUnless(os.environ.get('LEAKGUARD_GITLEAKS'), 'pinned Gitleaks required')
class NativeRuleInheritanceTests(unittest.TestCase):
    def test_whole_stdin_candidate_crosses_common_byte_read_boundary(self):
        # No product-level text chunking is implied by this check. The native
        # process receives the complete input, including a multibyte prefix.
        boundary = 65536
        prefix = 'é' + 'x' * (boundary - 7) + '\n'
        value = 'password=\"synthetic-cross-boundary\"'
        text = prefix + value + '\n'
        self.assertLess(len(prefix.encode()), boundary)
        self.assertGreater(len((prefix + value).encode()), boundary)
        command = [os.environ['LEAKGUARD_GITLEAKS'], 'stdin', '--config',
            str(Path(backends.__file__).with_name('rules.toml')), '--redact=100',
            '--ignore-gitleaks-allow', '--no-banner', '--no-color', '--log-level',
            'fatal', '--report-format', 'json', '--report-path', '-']
        completed = subprocess.run(command, input=text.encode(), capture_output=True, timeout=15)
        self.assertIn(completed.returncode, (0, 1))
        rows = json.loads(completed.stdout) or []
        self.assertTrue(any(row['RuleID'] == 'literal-password' and row['StartLine'] == 2
                            for row in rows))

    def test_inherited_false_substring_allowlist_suppresses_literals(self):
        # Direct bounded stdin check, no profile or scanner. Disabling defaults
        # is an experimental control only, not a proposed production change.
        text = '\n'.join((
            'password="falsehood-Synthetic-4829"',
            'password="synthetic-4829"',
            '{"password":"falsehood-Synthetic-4829","pwd":"synthetic-5829"}',
            '{"é":"😀","password":"synthetic-4829","pwd":"synthetic-5829"}',
            'password=false',
            'password=true',
            'password="false"',
            'password="synthetic-true-4829"',
        ))
        rule_file = Path(backends.__file__).with_name('rules.toml')
        rule_text = rule_file.read_text(encoding='utf-8')
        self.assertIn('useDefault = true', rule_text)
        def run_rules(config):
            command = [os.environ['LEAKGUARD_GITLEAKS'], 'stdin', '--config', str(config),
                '--redact=100', '--ignore-gitleaks-allow', '--no-banner', '--no-color',
                '--log-level', 'fatal', '--report-format', 'json', '--report-path', '-']
            completed = subprocess.run(command, input=text.encode(), capture_output=True, timeout=15)
            self.assertIn(completed.returncode, (0, 1))
            output = json.loads(completed.stdout) or []
            return [(row['StartLine'], row['StartColumn'], row['EndColumn'])
                    for row in output if row['RuleID'] == 'literal-password']
        with tempfile.TemporaryDirectory(prefix='synthetic-native-rules-') as folder:
            isolated = Path(folder) / 'rules.toml'
            isolated.write_text(rule_text.replace('useDefault = true', 'useDefault = false', 1),
                                encoding='utf-8')
            inherited = run_rules(rule_file)
            control = run_rules(isolated)
        self.assertCountEqual([row[0] for row in inherited], [2, 3, 4, 4, 6, 8])
        self.assertCountEqual([row[0] for row in control], [1, 2, 3, 3, 4, 4, 5, 6, 7, 8])
        # Pinned backend reports one-based UTF-8 byte columns here; a Unicode
        # prefix makes those differ from Python's character offsets.
        self.assertCountEqual([(start, end) for line, start, end in inherited if line == 4],
                              [(14, 41), (42, 64)])


if __name__ == '__main__':
    unittest.main()
