"""Authored synthetic labels: request an independent challenge before acceptance."""
import json
import os
from pathlib import Path
import sys
import unittest

from leakguard_core.backends import detect
from credential_detector.engine import scan_fields
from credential_detector.plugin import create_plugin

CASES = json.loads((Path(__file__).parent / 'fixtures/detection_dynamic_cases.json').read_text())['cases']


class DynamicReferenceCases(unittest.TestCase):
    def test_authored_cases_against_both_detectors(self):
        pack = create_plugin({}).pack
        policy = 'supervised-alpha' if sys.platform == 'darwin' else 'strict'
        for case in CASES:
            with self.subTest(case=case['id']):
                native = [item.rule for item in detect(case['text'], worker_policy=policy)
                          if item.rule in {'literal-password', 'credential-connection-url'}]
                plugin = [item.rule for item in scan_fields(case['text'], pack)]
                self.assertEqual(native, case['native'])
                self.assertEqual(plugin, case['plugin'])


if __name__ == '__main__':
    unittest.main()
