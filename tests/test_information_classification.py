"""Known information rules keep review/block policy without credential labels."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m, plugins


class InformationClassificationTests(unittest.TestCase):
    def test_actual_packs_classify_information_and_preserve_promotions(self):
        root = Path(__file__).resolve().parents[1]
        paths = [str(root / 'plugins/sensitive_basics/src'), str(root / 'templates/firm_plugin/src'), *sys.path]
        cases = [
            ('sensitive_basics.plugin', {}, b'customer_email=alex@example.invalid', 'pii-contact-email', m.FindingSeverity.REVIEW),
            ('sensitive_basics.plugin', {'promote-rules': ['pii-contact-email']}, b'customer_email=alex@example.invalid', 'pii-contact-email', m.FindingSeverity.BLOCK),
            ('firm_plugin', {}, b'customer_id: ACME-CUST-004812', 'firm-customer-number', m.FindingSeverity.REVIEW),
        ]
        with patch.object(sys, 'path', paths), patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', False)), patch.object(backends, 'detect', return_value=()):
            for module, options, text, rule, severity in cases:
                with self.subTest(module=module, promoted=bool(options)):
                    service = engine.ScanService({'plugins': [{'module': module, 'options': options}]})
                    try:
                        report = service.scan((m.BytesInput(text, 'synthetic.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(10, 1))
                        self.assertTrue(report.coverage.required_complete)
                        self.assertEqual(len(report.results[0].findings), 1)
                        finding = report.results[0].findings[0]
                        self.assertEqual(finding.rule, rule)
                        self.assertEqual(finding.classification, m.FindingClassification.HEURISTIC)
                        self.assertEqual(finding.severity, severity)
                    finally:
                        service.close()

    def test_unknown_credential_plugin_keeps_credential_classification(self):
        class CredentialPlugin:
            def detect(self, text, path, part):
                return (plugins.Finding('private-credential', 1, 'block'),)
        with patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', False)), patch.object(backends, 'detect', return_value=()):
            service = engine.ScanService({})
            service._plugins = [CredentialPlugin()]
            try:
                report = service.scan((m.BytesInput(b'synthetic', 'synthetic.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(10, 1))
                self.assertEqual(report.results[0].findings[0].classification, m.FindingClassification.CREDENTIAL_CANDIDATE)
            finally:
                service.close()
