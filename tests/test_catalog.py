"""Offline behavior checks for separated reports and companion history."""
import json
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import catalog
from leakguard_core import engine as guard
from leakguard_core import policies
from test_integration import SYNTHETIC


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='leakguard-test-', dir=pathlib.Path(tempfile.gettempdir()))
        self.root = pathlib.Path(self.temp.name)
        self.conn = sqlite3.connect(self.root / 'catalog.sqlite3')
        catalog.initialize(self.conn)

    def tearDown(self):
        self.conn.close()
        self.assertTrue(self.root.resolve().is_relative_to(pathlib.Path(tempfile.gettempdir()).resolve()))
        self.temp.cleanup()

    def test_share_aliases_have_one_identity(self):
        config = {'audit_scopes': {'share': r'\\server.example.invalid\shared'}, 'scope_aliases': {'share': ['R:\\']}, 'profiles': {'general': {'sources': ['share']}}}
        self.assertEqual(policies.canonical(r'R:\team\file.py', config), r'\\server.example.invalid\shared\team\file.py')
        self.assertEqual(policies.profile(r'R:\team\file.py', config), 'general')

    def test_integrity_digests_do_not_hide_credentials(self):
        digest = 'fd3862a9b10ce475d8263f9a1e70bc456a21d7fb940c8e5132f6d9a0b347ce85'
        text = json.dumps({'source_fingerprints': {'cache_service/api.py': digest}, 'sha256': digest, 'api_key': digest, 'client_secret': digest}, indent=2)
        findings, _ = guard.scan_blob(text.encode(), 'release.json')
        self.assertTrue(any(f['rule'] == 'literal-client-secret' for f in findings))

    def test_catalog_tracks_copies_changes_rename_and_deletion(self):
        one = str(self.root / 'one.txt'); two = str(self.root / 'two.txt'); renamed = str(self.root / 'renamed.txt')
        catalog.observe(self.conn, one, b'initial', guard.CONFIG)
        catalog.observe(self.conn, two, b'initial', guard.CONFIG)
        self.assertEqual(self.conn.execute('SELECT count(DISTINCT digest) FROM locations').fetchone()[0], 1)
        catalog.observe(self.conn, two, b'changed', guard.CONFIG)
        catalog.event(self.conn, renamed, 'renamed', guard.CONFIG, old_path=two)
        catalog.observe(self.conn, renamed, b'changed', guard.CONFIG)
        catalog.event(self.conn, renamed, 'deleted', guard.CONFIG)
        states = dict(self.conn.execute('SELECT path,present FROM locations'))
        self.assertEqual((states[one], states[two], states[renamed]), (1, 0, 0))
        kinds = [r[0] for r in self.conn.execute('SELECT kind FROM location_events')]
        self.assertIn('content-changed', kinds); self.assertIn('renamed', kinds); self.assertIn('deleted', kinds)

    def test_json_and_xml_passwords_are_detected(self):
        examples = [('settings.json', json.dumps({'password': SYNTHETIC})), ('app.config', '<add key="Password" value="' + SYNTHETIC + '" />')]
        for name, text in examples:
            found, _ = guard.scan_blob(text.encode(), name)
            self.assertTrue(any(f['rule'] in {'literal-password', 'xml-password'} for f in found), name)

    def test_known_material_tracking_does_not_persist_value(self):
        reference = self.root / 'reference.json'; reference.write_text(json.dumps({'value': SYNTHETIC}))
        self.conn.execute('INSERT INTO material_sources VALUES(?,?,?,?,?)', ('fixture-material', str(reference), 'json', 'value', 'credential')); self.conn.commit()
        path = str(self.root / 'copied.txt')
        matches = catalog.match_materials(self.conn, path, 'header\n' + SYNTHETIC, self.root)
        self.assertEqual(matches, [{'name': 'fixture-material', 'kind': 'credential', 'line': 2}])
        persisted = '\n'.join(self.conn.iterdump())
        self.assertNotIn(SYNTHETIC, persisted)
        catalog.match_materials(self.conn, path, 'removed', self.root)
        self.assertEqual(self.conn.execute('SELECT present FROM material_locations').fetchone()[0], 0)

    def test_location_is_visible_before_deep_content_scan(self):
        state = self.root / 'state'; (state / 'queue').mkdir(parents=True)
        target = self.root / 'new.txt'; target.write_text('Non-secret fixture')
        (state / 'queue' / 'event.json').write_text(json.dumps([{'path': str(target), 'kind': 'created'}]))

        def unavailable_content_scanner(path, conn, **kwargs):
            row = conn.execute('SELECT present,digest FROM locations WHERE path=?', (str(target),)).fetchone()
            self.assertEqual(row, (1, None))
            return {'path': str(path), 'status': 'timeout', 'findings': []}

        with patch.object(guard, 'STATE', state), patch.object(guard, 'scan_file', side_effect=unavailable_content_scanner):
            guard.drain()
        conn = sqlite3.connect(state / 'state.sqlite3')
        self.assertEqual(conn.execute('SELECT present FROM locations WHERE path=?', (str(target),)).fetchone()[0], 1)
        conn.close()

    def test_companion_reports_inventory_and_git_still_blocks(self):
        conn = guard.db()
        finding = guard.safe_findings([{'RuleID': 'literal-client-secret', 'StartLine': 1}], str(self.root / 'app.py'))
        companion = guard.save_report('fixture-companion', [{'findings': finding}], conn)
        git = guard.save_report('git-fixture', [{'findings': finding}], conn)
        general_finding = guard.safe_findings([{'RuleID': 'literal-client-secret', 'StartLine': 1}], r'\\server.example.invalid\shared\fixture\app.py')
        general = guard.save_report('fixture-general', [{'findings': general_finding}], conn)
        self.assertEqual(companion['findings'][0]['severity'], 'inventory')
        self.assertEqual(git['findings'][0]['severity'], 'block')
        self.assertEqual(general['findings'][0]['priority'], 'high')
        conn.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
