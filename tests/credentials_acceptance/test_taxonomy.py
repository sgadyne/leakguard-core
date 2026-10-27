"""Independent specification checks; execute against an installed candidate.

Only case IDs and rule IDs may be reported on failure. The optional sealed file
lives outside the checkout and is supplied by the acceptance owner.
"""
from __future__ import annotations

import importlib.resources as resources
import json
import os
from pathlib import Path
import shutil
import sys
import unittest

from credential_detector.engine import scan_fields
from credential_detector.http import scan_http
from credential_detector.aliases import load_packs
from leakguard_core import backends

GROUPS = ('common', 'cloud', 'developer-ci', 'data-messaging', 'saas-ai', 'key-material')
ROLES = {'password': 'credential-password', 'api-key': 'credential-api-key',
         'client-secret': 'credential-client-secret', 'access-token': 'credential-access-token',
         'private-key': 'credential-private-key'}


def fixtures():
    path = Path(os.environ.get('CREDENTIAL_ACCEPTANCE_FIXTURE', Path(__file__).with_name('development.json')))
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema') != 1:
        raise ValueError('fixture-schema')
    return data


def check(condition, label):
    if not condition:
        raise AssertionError(label)


class Taxonomy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = fixtures()
        cls.binary = os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks')
        if not cls.binary:
            raise RuntimeError('required-gitleaks-unavailable')
        cls.policy = 'supervised-alpha' if sys.platform == 'darwin' else 'strict'
        cls.pack = load_packs('credential_detector.resources', tuple(g + '.json' for g in GROUPS))
        cls.aliases = []
        for group in GROUPS:
            payload = resources.files('credential_detector').joinpath('resources', group + '.json').read_text(encoding='utf-8')
            doc = json.loads(payload)
            for alias in doc['aliases']:
                check(alias['group'] == group and alias['role'] in ROLES, 'pack-taxonomy')
                cls.aliases.append(alias)
        check(bool(cls.aliases), 'empty-packs')
        check({a['group'] for a in cls.aliases} == set(GROUPS), 'missing-group')

    def test_all_aliases(self):
        templates = self.data['field_templates']
        for alias in self.aliases:
            key, rule = alias['name'], ROLES[alias['role']]
            for kind, text, expected in (
                ('short', 'π\n' + key + ' = "' + templates['literal'] + '"\n', True),
                ('quoted-reference', key + ' = "' + templates['quoted_reference'] + '"\n', True),
                ('unquoted-reference', key + ' = ' + templates['reference'] + '\n', False),
                ('prefix', templates['near_prefix'] + key + ' = "' + templates['literal'] + '"\n', False),
                ('suffix', key + templates['near_suffix'] + ' = "' + templates['literal'] + '"\n', False),
            ):
                with self.subTest(group=alias['group'], alias=key, case=kind):
                    spans = scan_fields(text, self.pack)
                    found = [span for span in spans if span.rule == rule]
                    check(bool(found) == expected, 'alias-' + kind)
                    for span in spans:
                        check(0 <= span.start < span.end <= len(text), 'alias-span-bounds')
                        check(templates['literal'] not in repr(span) and templates['quoted_reference'] not in repr(span), 'alias-span-privacy')
                    if kind == 'short' and found:
                        pos = text.index(templates['literal'])
                        check(found[0].start <= pos and found[0].end >= pos + len(templates['literal']), 'alias-original-offset')

    def test_http_cases(self):
        for row in self.data['cases']:
            if row['family'] != 'http':
                continue
            with self.subTest(case=row['id']):
                spans = scan_http(row['text'])
                matching = [s for s in spans if s.rule == row['rule']] if row['rule'] else spans
                check(bool(matching) == bool(row['rule']), 'http-expectation')
                for span in spans:
                    check(0 <= span.start < span.end <= len(row['text']), 'http-span-bounds')
                    if row['fragment']:
                        start = row['text'].index(row['fragment'])
                        check(span.start == start and span.end == start + len(row['fragment']), 'http-original-offset')
                        check(row['fragment'] not in repr(span), 'http-span-privacy')

    def test_url_cases(self):
        for row in self.data['cases']:
            if row['family'] != 'url':
                continue
            with self.subTest(case=row['id']):
                findings = backends.detect(row['text'], binary=self.binary, worker_policy=self.policy)
                matching = [f for f in findings if f.rule == 'credential-connection-url']
                check(bool(matching) == bool(row['rule']), 'url-expectation')
                check(all(f.severity == 'block' and f.start_line == 1 and f.end_line == 1 for f in matching), 'url-action-location')
                check(row['text'] not in repr(findings), 'url-finding-privacy')

    def test_protocol_bounds(self):
        # No unbounded decoding/output or invalid spans for oversized inputs.
        texts = ('Authorization: Basic ' + 'A' * 100_000 + '\n',
                 'Authorization: Bearer ' + 'z' * 100_000 + '\n')
        for text in texts:
            with self.subTest(case='oversized-protocol'):
                spans = scan_http(text)
                check(len(spans) <= 1, 'http-output-bound')
                check(all(0 <= s.start < s.end <= len(text) for s in spans), 'http-large-span')


if __name__ == '__main__':
    unittest.main(verbosity=2)
