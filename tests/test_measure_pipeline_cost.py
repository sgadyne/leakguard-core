"""Safety and comparison controls for the synthetic cost harness."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace as NS
from dataclasses import replace

spec=importlib.util.spec_from_file_location('measure_pipeline_cost',Path(__file__).resolve().parents[1]/'tools/measure_pipeline_cost.py')
cost=importlib.util.module_from_spec(spec)
spec.loader.exec_module(cost)

class FixtureTests(unittest.TestCase):
    def read(self,value):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.json'
            path.write_text(json.dumps(value))
            return cost.fixture(path)[0]
    def test_text_and_binary_decode_exactly(self):
        rows=self.read({'synthetic_only':True,'files':[{'name':'a.txt','text':'hello'}, {'name':'b.bin','base64':'AP8='}]})
        self.assertEqual([x['payload'] for x in rows],[b'hello',b'\x00\xff'])
    def test_rejects_invalid_or_unsafe_inputs(self):
        for item in ({'name':'../escape','text':'x'},{'name':'x','base64':'@!'}, {'name':'x','text':'x','base64':'eA=='}, {'name':'x','base64':'QQ==\n'}):
            with self.subTest(item=item),self.assertRaises(ValueError):
                self.read({'synthetic_only':True,'files':[item]})
        with self.assertRaises(ValueError):
            self.read({'synthetic_only':False,'files':[{'name':'x','text':'x'}]})


class SignatureTests(unittest.TestCase):
    def test_provenance_span_and_omissions_change_signature(self):
        from leakguard_core.models import AnalysisMetadata
        root=Path('/synthetic-fixture')
        value=lambda x:NS(value=x)
        analysis=AnalysisMetadata(1,2,8,'JOSE_COMPACT_JWE',0.99,'recognizer','analyzer','1','model')
        finding=NS(part_id='text',rule='synthetic-rule',detector_severity=value('block'),
            severity=value('block'),start_line=1,end_line=1,classification=value('credential'),
            detector_id='detector-a',analysis=analysis)
        result=NS(source=NS(path=str(root/'a.txt')),coverage=value('complete'),content=NS(digest='a'*64),
            identity=NS(policy_id='policy',runtime_id='runtime',context_id='context'),findings=[finding],issues=[])
        coverage=NS(omission_count=0,pending_files=None,pending_directories=None,enumeration_complete=True,required_complete=True)
        report=NS(results=[result],issues=[],coverage=coverage,decision=NS(verdict=value('block'),reason_codes=()))
        original=cost.signature(report,root)[0]
        finding.detector_id='detector-b'
        self.assertNotEqual(original,cost.signature(report,root)[0])
        finding.detector_id='detector-a';finding.analysis=replace(analysis,end=9)
        self.assertNotEqual(original,cost.signature(report,root)[0])
        finding.analysis=analysis;coverage.omission_count=1
        self.assertNotEqual(original,cost.signature(report,root)[0])

if __name__ == '__main__':
    unittest.main()
