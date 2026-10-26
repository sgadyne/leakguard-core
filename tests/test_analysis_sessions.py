"""Versioned value-free results and bounded warm extension lifecycle."""
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from leakguard_core import models as m, plugins as p, engine
from leakguard_core.api import parse_report


MODULE = '''
from pathlib import Path
from leakguard_core.plugins import *
API_VERSION=2
MANIFEST=PluginManifest(id='session-fixture',implementation_version='1',kind='detector',
 rules=(RuleSpec('fixture-entity'),),formats=('text',),part_kinds=('text',),
 options_schema=OptionSchema((OptionSpec('record','string',required=True),)),
 worker_lifetime='session',result_schema=2)
class Detector:
 def __init__(self,options):
  self.record=Path(options['record']); self.calls=0
  with self.record.open('a') as f:f.write('factory\\n')
 def detect(self,text,context):
  self.calls+=1
  for start,end in ((0,2),(3,5)):
   yield NewFinding('fixture-entity',1,'review',AnalysisMetadata(1,start,end,'FIRM_ID',self.calls/10,'firm-fixture','fixture','1','pattern-only'))
 def close(self):
  with self.record.open('a') as f:f.write('close\\n')
def create_plugin(options):return Detector(options)
'''


class AnalysisSessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'session_fixture.py').write_text(MODULE)
        self.environment = patch.dict(os.environ, {'PYTHONPATH': str(self.root)})
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.spec = {'module': 'session_fixture', 'options': {'record': str(self.root / 'lifecycle')}}

    def test_inspect_no_factory_and_two_requests_share_one_instance_with_normal_close(self):
        instances = p.load([self.spec], worker_policy='supervised-alpha')
        self.assertFalse((self.root / 'lifecycle').exists())
        try:
            first = list(p.detect(instances, 'ab cd', 'one.txt', 'text', worker_policy='supervised-alpha'))
            second = list(p.detect(instances, 'ab cd', 'two.txt', 'text', worker_policy='supervised-alpha'))
            self.assertEqual([x.analysis.score for x in first], [.1, .1])
            self.assertEqual([x.analysis.score for x in second], [.2, .2])
            self.assertEqual(p.session_metrics(instances)[0]['starts'], 1)
            self.assertEqual(p.session_metrics(instances)[0]['requests'], 2)
            process = instances[0].session.worker.process
        finally:
            p.close(instances)
        self.assertEqual((self.root / 'lifecycle').read_text().splitlines(), ['factory', 'close'])
        self.assertEqual(process.returncode, 0)

    def test_two_spans_same_rule_line_survive_report_and_store_roundtrip(self):
        from leakguard_core import backends
        with patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', False)), patch.object(backends, 'detect', return_value=()):
            service = engine.ScanService({'plugins': [self.spec], 'worker_policy': 'supervised-alpha'})
            try:
                report = service.scan([m.BytesInput(b'ab cd', 'fixture.txt')], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(10, 1))
                self.assertTrue(report.coverage.required_complete)
                findings = report.results[0].findings
                self.assertEqual(len(findings), 2)
                self.assertNotEqual(findings[0].id, findings[1].id)
                self.assertEqual({f.severity for f in findings}, {m.FindingSeverity.REVIEW})
                self.assertEqual({f.classification for f in findings}, {m.FindingClassification.HEURISTIC})
                self.assertEqual(parse_report(report.to_json()), report)
                self.assertEqual(service.store.query_findings_page(state='history', limit=10).rows[0]['analysis']['schema_version'], 1)
            finally:
                service.close()

    def test_invalid_offset_score_extra_fields_and_legacy_schema_are_rejected(self):
        with self.assertRaises(ValueError):
            m.AnalysisMetadata(1, 0, 1, 'ID', float('nan'), 'fixed', 'fixed', '1', 'none')
        good = m.AnalysisMetadata(1, 0, 2, 'ID', .01, 'fixed', 'fixed', '1', 'none')
        legacy = p.PluginManifest(id='fixture', implementation_version='1', kind='detector', rules=(p.RuleSpec('fixture-entity'),))
        with self.assertRaises(p.PluginError):
            list(p._validated_findings([p.NewFinding('fixture-entity', 1, 'review', good)], 'ab', legacy))
        manifest = p.PluginManifest(id='fixture', implementation_version='1', kind='detector', rules=(p.RuleSpec('fixture-entity'),), result_schema=2)
        with self.assertRaises(p.PluginError):
            list(p._validated_findings([p.NewFinding('fixture-entity', 1, 'review', good)], 'a', manifest))
        with self.assertRaises(TypeError):
            m.AnalysisMetadata(**dict(schema_version=1,start=0,end=1,entity_type='ID',score=.5,recognizer_id='fixed',analyzer_id='fixed',analyzer_version='1',model_id='none',matched_text='forbidden'))

    def test_session_timeout_is_bounded_and_reaps_worker(self):
        from leakguard_core._session import FramedWorker
        import sys
        worker = FramedWorker([sys.executable, '-I', '-c', 'import time;time.sleep(30)'], worker_policy='supervised-alpha')
        started = time.monotonic()
        try:
            with self.assertRaises(Exception) as failure:
                worker.request(b'{}', timeout=.1)
            self.assertEqual(failure.exception.code, 'worker-timeout')
            self.assertLess(time.monotonic() - started, 2)
            self.assertIsNotNone(worker.process.poll())
        finally:
            worker.close()


if __name__ == '__main__':
    unittest.main()
