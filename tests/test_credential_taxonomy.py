"""Synthetic regression cases for the default, offline credential detector."""
import base64
import os
import json
import shutil
import sys
import tempfile
import unittest
from urllib.parse import quote

from leakguard_core import backends, engine, models

SCHEMES = ('postgres', 'postgresql', 'mysql', 'mariadb', 'mongodb',
           'mongodb+srv', 'redis', 'rediss', 'amqp', 'amqps')


def _synthetic_alnum(size):
    # Deliberately non-secret fixtures, assembled at runtime.
    return ("Az8mN4qR1tY6pC3vK9wD2jH5sB7fG0xL" * ((size // 32) + 1))[:size]


class CredentialTaxonomyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks')
        if not cls.binary:
            raise unittest.SkipTest('Gitleaks is not installed')
        cls.worker_policy = 'supervised-alpha' if sys.platform == 'darwin' else 'strict'

    def detect(self, text):
        return backends.detect(text, binary=self.binary, worker_policy=self.worker_policy)

    def test_core_provider_and_container_examples(self):
        a = _synthetic_alnum
        cases = [
            ('aws-access-token', 'AKIA' + 'BCDEFGHIJKLMNPQR'),
            ('github-pat', 'ghp_' + a(36)),
            ('github-fine-grained-pat', 'github_pat_' + a(82)),
            ('gitlab-pat', 'glpat-' + a(20)),
            ('gcp-api-key', 'AIza' + a(35)),
            ('anthropic-api-key', 'sk-ant-api03-' + a(93) + 'AA'),
            ('openai-api-key', 'sk-' + a(20) + 'T3BlbkFJ' + a(20)),
            ('huggingface-access-token', 'hf_' + 'abcdefghij' * 3 + 'abcd'),
            ('npm-access-token', 'npm_' + a(36)),
            ('pypi-upload-token', 'pypi-AgEIcHlwaS5vcmc' + a(55)),
            ('databricks-api-token', 'dapi' + 'a193b7c45d82e0f1' * 2),
            ('digitalocean-pat', 'dop_v1_' + 'a193b7c45d82e0f1' * 4),
            ('stripe-access-token', 'sk_live_' + a(24)),
            ('slack-bot-token', 'xoxb-12345678901-98765432109-' + a(24)),
            ('sendgrid-api-token', 'SG.' + a(66)),
            ('private-key', '-----BEGIN PRIVATE KEY-----\n' + a(80) + '\n-----END PRIVATE KEY-----'),
            ('literal-password', 'password = "synthetic password phrase"'),
            ('literal-client-secret', 'client_secret = "synthetic-secret-value"'),
        ]
        for expected, text in cases:
            with self.subTest(rule=expected):
                findings = self.detect(text)
                self.assertIn(expected, {f.rule for f in findings})
                self.assertTrue(all(f.severity == 'block' for f in findings))
                self.assertNotIn(text, repr(findings))

    def test_connection_urls_block_literal_passwords(self):
        cases = {
            'postgres': 'postgres://alice:short@db.internal:5432/app',
            'postgresql': 'postgresql://alice:K7fx9yQP2mR8@db.internal/app',
            'mysql': 'mysql://bob:p%40ss-word@db.internal:3306/app',
            'mariadb': 'mariadb://bob:aBc123@[2001:db8::1]:3306/app',
            'mongodb': 'mongodb://bob:q2Kf78nZ14@db.internal/app',
            'mongodb+srv': 'mongodb+srv://bob:q2Kf78nZ14@db.internal/app',
            'redis': 'redis://:q2Kf78nZ14@cache.internal:6379/0',
            'rediss': 'rediss://alice:q2Kf78nZ14@cache.internal/0',
            'amqp': 'amqp://alice:q2Kf78nZ14@mq.internal/vhost',
            'amqps': 'amqps://alice:q2Kf78nZ14@mq.internal/vhost',
        }
        for scheme, url in cases.items():
            with self.subTest(scheme=scheme):
                findings = self.detect('connection = "' + url + '"')
                own = [f for f in findings if f.rule == 'credential-connection-url']
                self.assertEqual(len(own), 1)
                self.assertEqual(own[0].severity, 'block')
                self.assertNotIn(url, repr(findings))

    def test_each_connection_scheme_requires_a_password(self):
        for scheme in SCHEMES:
            with self.subTest(scheme=scheme):
                findings = self.detect(scheme + '://alice@host.example/db')
                self.assertNotIn('credential-connection-url', {f.rule for f in findings})

    def test_connection_url_authority_and_boundaries(self):
        # Labels distinguish cases without emitting synthetic input on failure.
        positives = {
            'case': 'POSTGRESQL://u:p@DB.EXAMPLE',
            'one-character': 'redis://:x@h',
            'percent-user-and-password': 'mysql://u%40x:p%3Ass@host/path',
            'embedded-encoded-marker': 'mysql://u:p%24DB_PASSWORD@host/path',
            'embedded-encoded-template': 'mysql://u:p%7b%7bPASSWORD%7d%7d@host/path',
            'encoded-high-byte': 'mysql://u:p%c3%a9@host/path',
            'userinfo-punctuation': 'amqp://u-._~!*+;=:p-._~!*+;=:@host?v=1',
            'ip-host': 'postgres://u:p@127.0.0.1:1/db',
            'bracket-ipv6': 'postgres://u:p@[::1]:65535/db',
            'port-zero': 'redis://u:p@host:0#part',
            'quoted': '["postgres://u:p@host"]',
            'square-bracket': '[mysql://u:p@host/db]',
            'semicolon': ';mysql://u:p@host/db',
            'assignment': 'url=postgres://u:p@host;',
        }
        negatives = {
            'no-userinfo': 'postgres://host/db',
            'no-password-separator': 'postgres://alice@host/db',
            'empty-password': 'postgres://alice:@host/db',
            'empty-host': 'postgres://alice:p@/db',
            'unsupported-scheme': 'https://alice:p@host/db',
            'jdbc': 'jdbc:postgresql://alice:p@host/db',
            'odbc': 'odbc:postgresql://alice:p@host/db',
            'scheme-prefix': 'xpostgres://alice:p@host/db',
            'scheme-plus-prefix': 'x+postgres://alice:p@host/db',
            'scheme-dash-prefix': 'x-postgres://alice:p@host/db',
            'bad-scheme': 'postgresx://alice:p@host/db',
            'nondecimal-port': 'postgres://alice:p@host:abc/db',
            'empty-port': 'postgres://alice:p@host:/db',
            'port-too-long': 'postgres://alice:p@host:123456/db',
            'port-out-of-range': 'postgres://alice:p@host:65536/db',
            'host-double-dot': 'postgres://alice:p@host..example/db',
            'host-leading-dash': 'postgres://alice:p@-host/db',
            'host-trailing-dash': 'postgres://alice:p@host-/db',
            'triple-colon-bracket': 'postgres://alice:p@[:::]/db',
            'unclosed-bracket': 'postgres://alice:p@[::1/db',
            'bracket-dns': 'postgres://alice:p@[host]/db',
            'unbracketed-ipv6': 'postgres://alice:p@::1/db',
            'garbage-after-bracket': 'postgres://alice:p@[::1]extra/db',
            'bad-percent-user': 'mysql://u%Q1:p@host/db',
            'short-percent-user': 'mysql://u%1:p@host/db',
            'bad-percent-password': 'mysql://u:p%Q1@host/db',
            'short-percent-password': 'mysql://u:p%1@host/db',
            'encoded-cr': 'mysql://u:p%0Dword@host/db',
            'encoded-lf': 'mysql://u:p%0aword@host/db',
            'encoded-environment-braces': 'mysql://u:%24%7BDB_PASSWORD%7D@host/db',
            'encoded-environment-dollar': 'mysql://u:%24DB_PASSWORD@host/db',
            'encoded-environment-percent': 'mysql://u:%25DB_PASSWORD%25@host/db',
            'encoded-angle-placeholder': 'mysql://u:%3CPASSWORD%3E@host/db',
            'encoded-brace-placeholder': 'mysql://u:%7b%7bPASSWORD%7d%7d@host/db',
            'environment-braces': 'postgres://alice:${DB_PASSWORD}@host/db',
            'environment-dollar': 'postgres://alice:$DB_PASSWORD@host/db',
            'environment-percent': 'postgres://alice:%DB_PASSWORD%@host/db',
            'template': 'postgres://alice:{{password}}@host/db',
            'angle-placeholder': 'postgres://alice:<password>@host/db',
        }
        for expected, cases in ((True, positives), (False, negatives)):
            for label, text in cases.items():
                with self.subTest(case=label):
                    found = any(f.rule == 'credential-connection-url' for f in self.detect(text))
                    self.assertEqual(found, expected)

    def test_adjacent_urls_are_independently_evaluated(self):
        placeholder = 'mysql://u:%24FOO@host'
        literal = 'mysql://v:b@host'
        cases = {
            'placeholder-first-space': (placeholder + ' ' + literal, 1),
            'placeholder-first-comma': (placeholder + ',' + literal, 1),
            'literal-first-space': (literal + ' ' + placeholder, 1),
            'both-literal-space': (literal + ' mysql://w:c@host', 2),
            'both-literal-comma': (literal + ',mysql://w:c@host', 2),
            'both-literal-newline': (literal + '\nmysql://w:c@host', 2),
            'both-literal-crlf': (literal + '\r\nmysql://w:c@host', 2),
            'three-literals': (literal + ' mysql://w:c@host mysql://z:d@host', 3),
            'invalid-prefix-first': ('x+postgres://u:p@host ' + literal, 1),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(case=label):
                own = [f for f in self.detect(text) if f.rule == 'credential-connection-url']
                self.assertEqual(len(own), expected)

    def test_percent_encoded_ascii_controls_are_rejected(self):
        # All C0 octets and DEL, in both user and password positions. High
        # bytes remain lexical and are not decoded as Unicode by this rule.
        cases = []
        for byte in (*range(0x20), 0x7f):
            encoded = f'%{byte:02x}'
            cases.extend(('mysql://u' + encoded + ':p@host',
                          'mysql://u:p' + encoded + '@host'))
        findings = self.detect('\n'.join(cases))
        self.assertNotIn('credential-connection-url', {f.rule for f in findings})

    def test_bare_authority_finding_stays_on_its_source_line(self):
        for name, separator in (('lf', '\n'), ('crlf', '\r\n')):
            with self.subTest(separator=name):
                text = separator.join(('before', 'mysql://u:p@host', 'after'))
                own = [f for f in self.detect(text) if f.rule == 'credential-connection-url']
                self.assertEqual(len(own), 1)
                self.assertEqual((own[0].start_line, own[0].end_line), (2, 2))

    def test_percent_encoded_utf8_c1_controls_are_rejected(self):
        cases = []
        for byte in range(0x80, 0xa0):
            encoded = f'%c2%{byte:02x}'
            cases.extend(('mysql://u' + encoded + ':p@host',
                          'mysql://u:p' + encoded + '@host'))
        findings = self.detect('\n'.join(cases))
        self.assertNotIn('credential-connection-url', {f.rule for f in findings})

    def test_gitleaks_decoded_input_is_subject_to_same_rule_controls(self):
        # Gitleaks 8.30.1 decodes whole input independently of this regex.
        def encode(value):
            return base64.b64encode(value.encode()).decode()
        literal = 'mysql://u:Literal42@host'
        placeholder = 'mysql://u:%7b%7bPASSWORD%7d%7d@host'
        reference = 'mysql://u:%24FOO@host'
        control = 'mysql://u:p%09word@host'
        cases = {
            'base64-literal': (encode(literal), True),
            'nested-base64-literal': (encode(encode(literal)), True),
            'percent-literal': (quote(literal, safe=''), True),
            'base64-placeholder': (encode(placeholder), False),
            'nested-base64-placeholder': (encode(encode(placeholder)), False),
            'percent-placeholder': (quote(placeholder, safe=''), False),
            'base64-reference': (encode(reference), False),
            'percent-reference': (quote(reference, safe=''), False),
            'base64-control': (encode(control), False),
            'nested-base64-control': (encode(encode(control)), False),
            'percent-control': (quote(control, safe=''), False),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(case=label):
                found = any(f.rule == 'credential-connection-url' for f in self.detect(text))
                self.assertEqual(found, expected)

    def test_connection_url_produces_redacted_blocking_scan_result(self):
        urls = [scheme + '://alice:K7fx9yQP2mR8@db.internal/app'
                for scheme in SCHEMES]
        content = 'first line\n' + ''.join('connection = "' + url + '"\n' for url in urls)
        content += 'mysql://u:%24FOO@host mysql://v:Adjacent42@host\n'
        encoded = base64.b64encode(b'mysql://u:Encoded42@host').decode()
        with tempfile.TemporaryDirectory(prefix='leakguard-credential-test-') as state:
            service = engine.ScanService({
                'gitleaks_executable': self.binary,
                'worker_policy': self.worker_policy,
            }, state_dir=state)
            try:
                report = service.scan(
                    [models.BytesInput(content.encode(), 'config.txt')],
                    policy=models.ScanPolicy.inventory(),
                    limits=models.ScanLimits(30, 1), use_cache=False,
                )
                wrapped_report = service.scan(
                    [models.BytesInput(encoded.encode(), 'encoded.txt')],
                    policy=models.ScanPolicy.inventory(),
                    limits=models.ScanLimits(30, 1), use_cache=False,
                )
                mixed_report = service.scan(
                    [models.BytesInput((content + encoded + '\n').encode(), 'mixed.txt')],
                    policy=models.ScanPolicy.inventory(),
                    limits=models.ScanLimits(30, 1), use_cache=False,
                )
            finally:
                service.close()
        self.assertEqual(report.decision.verdict, models.DecisionVerdict.BLOCK)
        own = [finding for result in report.results for finding in result.findings
               if finding.rule == 'credential-connection-url']
        self.assertEqual(len(own), len(SCHEMES) + 1)
        self.assertTrue(all(f.severity == models.FindingSeverity.BLOCK for f in own))
        self.assertEqual({(f.start_line, f.end_line) for f in own},
                         {(line, line) for line in range(2, 13)})
        serialized = json.dumps(report.to_dict())
        for value in (*urls, 'K7fx9yQP2mR8', 'Adjacent42', 'Encoded42', encoded, content):
            self.assertNotIn(value, serialized)
            self.assertNotIn(value, repr(report))
        self.assertEqual(wrapped_report.decision.verdict, models.DecisionVerdict.BLOCK)
        wrapped = [finding for result in wrapped_report.results for finding in result.findings
                   if finding.rule == 'credential-connection-url']
        self.assertEqual(len(wrapped), 1)
        self.assertEqual(wrapped[0].severity, models.FindingSeverity.BLOCK)
        self.assertEqual((wrapped[0].start_line, wrapped[0].end_line), (1, 1))
        self.assertNotIn(encoded, json.dumps(wrapped_report.to_dict()))
        self.assertNotIn('Encoded42', json.dumps(wrapped_report.to_dict()))
        self.assertNotIn(encoded, repr(wrapped_report))
        mixed = [finding for result in mixed_report.results for finding in result.findings
                 if finding.rule == 'credential-connection-url']
        self.assertEqual(len(mixed), len(SCHEMES) + 2)
        self.assertEqual({(f.start_line, f.end_line) for f in mixed},
                         {(line, line) for line in range(2, 14)})
        self.assertEqual(mixed_report.decision.verdict, models.DecisionVerdict.BLOCK)
        self.assertNotIn(encoded, json.dumps(mixed_report.to_dict()))


if __name__ == '__main__':
    unittest.main()
