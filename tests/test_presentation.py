"""Security and usability checks for JSON context and redacted Git summaries."""
import ast
import hashlib
import json
import pathlib
import tempfile
import unittest

from leakguard_core import finding_details as details
from leakguard_core import engine as guard
from leakguard_core import presentation


class PresentationTests(unittest.TestCase):
    def test_compact_or_duplicate_json_cannot_grant_exemption_to_another_value(self):
        source = b'def token(value):\n    return value\n'
        digest = hashlib.sha256(ast.dump(ast.parse(source).body[0]).encode()).hexdigest()
        document = {'scope.py': {'function_ast_sha256': {'token': digest}}, 'api_key': 'NeverDisplayThisPrivateFixture'}
        finding = {'path': 'origins.json', 'line': 1, 'rule': 'generic-api-key', 'severity': 'block'}
        result = details.describe(finding, json.dumps(document).encode(), lambda _: source)
        self.assertEqual(result['severity'], 'block')
        duplicate = ('{"scope.py":{"function_ast_sha256":{"token":"' + digest + '","token":"other"}}}').encode()
        self.assertEqual(details.describe(finding, duplicate, lambda _: source)['severity'], 'block')

    def test_summary_has_location_commit_and_type_but_never_raw_engine_fields(self):
        fixture_value = 'NeverDisplayThisPrivateFixture'
        report = {'label': 'git-pre-push', 'repo': r'C:\repo', 'findings': [{'path': r'C:\repo\settings.json', 'line': 5, 'commit': 'a' * 40, 'rule': 'generic-api-key', 'severity': 'block', 'field': 'api_key', 'info': 'Possible API key/token', 'Secret': fixture_value, 'Match': fixture_value, 'Line': fixture_value}]}
        output = presentation.render(report)
        self.assertIn('settings.json:5', output)
        self.assertIn('[aaaaaaaaaaaa]', output)
        self.assertIn('generic-api-key', output)
        self.assertIn('values are redacted', output)
        self.assertNotIn('api_key', output)
        self.assertNotIn('Possible API key/token', output)
        self.assertNotIn(fixture_value, output)
        self.assertNotIn(fixture_value, json.dumps(presentation.sanitized_report(report)))
        self.assertNotIn('Possible API key/token', json.dumps(presentation.sanitized_report(report)))

    def test_report_lookup_stays_with_the_requested_repo(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-test-', dir=pathlib.Path(tempfile.gettempdir())) as folder:
            state = pathlib.Path(folder); (state / 'reports').mkdir()
            own = state / 'reports' / 'old-git-pre-push.json'
            own.write_text(json.dumps({'label': 'git-pre-push', 'repo': r'C:\one', 'findings': []}))
            other = state / 'reports' / 'new-git-pre-push.json'
            other.write_text(json.dumps({'label': 'git-pre-push', 'repo': r'C:\two', 'findings': []}))
            self.assertEqual(presentation.select_report(state, repo=r'C:\one'), own)
            with self.assertRaises(ValueError):
                presentation.select_report(state, repo=r'C:\missing')


if __name__ == '__main__':
    unittest.main(verbosity=2)
