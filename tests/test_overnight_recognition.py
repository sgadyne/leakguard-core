"""Labelled synthetic close controls for LG-A008, LG-A009 and LG-A011.

These tests characterize existing detector outputs; line-only native locations
are not proof that two observations refer to the same value.
"""
import base64
import json
import os
import unittest

from credential_detector.engine import scan_fields
from credential_detector.plugin import CredentialDetector
from jose_recognizers.scanner import scan_compact_tokens
from leakguard_core import backends
from leakguard_core.artifact_context import inspect_artifact

def segment(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def token(offset=0):
    header = segment(json.dumps({'alg':'A256KW','enc':'A256GCM'},separators=(',',':')).encode())
    return '.'.join((header, segment(bytes(range(offset,offset+40))),
        segment(bytes(range(offset,offset+12))), segment(bytes(range(offset,offset+64))),
        segment(bytes(range(offset,offset+16)))))

class LabelledRecognitionTests(unittest.TestCase):
    def test_jose_two_fields_on_one_line_keep_distinct_structural_spans(self):
        a,b=token(),token(40)
        text=json.dumps({'api_key':a,'password':b})
        jose=scan_compact_tokens(text)
        self.assertEqual([m.entity_type for m in jose], ['JOSE_COMPACT_JWE']*2)
        self.assertEqual([text[m.start:m.end] for m in jose], [a,b])
        fields=scan_fields(text,CredentialDetector().pack)
        self.assertEqual([(m.rule,text[m.start:m.end]) for m in fields],
            [('credential-api-key',a),('credential-password',b)])
        self.assertEqual(scan_compact_tokens(a.replace('.', '', 1)), [])
        if os.environ.get('LEAKGUARD_GITLEAKS'):
            native=backends.detect(text,binary=os.environ['LEAKGUARD_GITLEAKS'])
            self.assertIn('literal-password',{x.rule for x in native})
            self.assertTrue(all(x.start_line == 1 for x in native))
            self.assertTrue(all(not hasattr(x,'start_column') for x in native))

    def test_binary_plist_only_reviewable_with_unmixed_interior(self):
        marker='EAAA'+('Az8mN4qR1tY6pC3vK9wD2jH5sB7fG0xL'*2)[:60]
        head=base64.b64encode(b'bplist00x').decode()
        make=lambda body: '<?xml version="1.0"?><plist version="1.0"><dict>'+body+'</dict></plist>'
        binary=make('<key>payload</key><data>\n'+head+'\n'+marker+'\n</data>')
        mixed=make('<key>payload</key><data>\n'+head+'\n'+marker+' </data><key>password</key><string>synthetic-literal</string>')
        malformed=binary.replace('</plist>','')
        self.assertEqual(inspect_artifact(binary).binary_lines,((2,3),))
        self.assertFalse(any(start <= 3 <= end for start,end in inspect_artifact(mixed).binary_lines))
        self.assertEqual(inspect_artifact(malformed).binary_lines,())
        if os.environ.get('LEAKGUARD_GITLEAKS'):
            detect=lambda x: [f for f in backends.detect(x,binary=os.environ['LEAKGUARD_GITLEAKS']) if f.rule=='square-access-token']
            self.assertEqual([x.severity for x in detect(binary)],['review'])
            self.assertEqual([x.severity for x in detect(marker)],['block'])
            mixed_rows=detect(mixed)
            self.assertTrue(mixed_rows)
            self.assertTrue(all(x.severity=='block' for x in mixed_rows))

    def test_signature_review_requires_schema_and_no_literal_sibling(self):
        aws='AKIA'+'BCDEFGHIJKLMNPQR'
        regex='(?i)^('+r'\\w+'*350+')'+aws+'$'
        known=json.dumps([{'hash':'a193b7c4'*8,'regex':regex}])
        sibling=json.dumps([{'hash':'a193b7c4'*8,'regex':regex,'api_key':aws}])
        truncated=known[:-1]
        self.assertEqual(inspect_artifact(known).aws_review_lines,frozenset({1}))
        self.assertFalse(inspect_artifact(sibling).aws_review_lines)
        self.assertFalse(inspect_artifact(truncated).aws_review_lines)
        if os.environ.get('LEAKGUARD_GITLEAKS'):
            detect=lambda x: [f for f in backends.detect(x,binary=os.environ['LEAKGUARD_GITLEAKS']) if f.rule=='aws-access-token']
            for text,expected in ((known,'review'),(sibling,'block'),(json.dumps({'aws_access_key_id':aws}),'block')):
                rows=detect(text)
                self.assertTrue(rows)
                self.assertTrue(all(x.severity==expected for x in rows))

if __name__ == '__main__':
    unittest.main()
