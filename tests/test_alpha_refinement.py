"""Live-observation grammar/schema regressions using synthetic values only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from leakguard_core import backends
from leakguard_core.artifact_context import inspect_artifact, is_rsa_public_spki, mask_artifact_labels
from leakguard_core.credential_syntax import mask_nonliteral_labels
from credential_detector.engine import scan_fields
from credential_detector.plugin import CredentialDetector

TOKEN = 'Az8mN4qR1tY6pC3vK9wD2jH5sB7fG0xL'
HEX = 'a193b7c45d82e0f1' * 2 + 'a193b7c4'


def der(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + content


def public_spki():
    modulus = b'\x00\xc3' + b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(8))[:255]
    public = der(0x30, der(2, modulus) + der(2, b'\x01\x00\x01'))
    algorithm = der(0x30, bytes.fromhex('06092a864886f70d0101010500'))
    return base64.b64encode(der(0x30, algorithm + der(3, b'\0' + public))).decode()


def plist(body):
    return '<?xml version="1.0"?><plist version="1.0"><dict>' + body + '</dict></plist>'


class SharedGrammarTests(unittest.TestCase):
    def setUp(self):self.pack = CredentialDetector().pack
    def fields(self, text, path=''):
        return scan_fields(text, self.pack, logical_path=path)
    def test_declarations_references_and_quoted_counterparts(self):
        cases = [
            ('password: string;', 'types.d.ts'),
            ('func a(password: String, refreshToken: String?) {}', 'Auth.swift'),
            ('password:(NSString *)password;', 'Auth.h'),
            ('if password == "synthetic-comparison":', 'config.py'),
            ('password = nil', 'config.rb'),
            ('pwd = self.pwd', 'zipfile.py'),
            ('self.pwd = pwd', 'zipfile.py'),
            ('def open(pwd=None):', 'zipfile.py'),
            ('password:%s', 'config.py'),
            ('Password: <type your password>', 'manual.txt'),
            ('const opts = { password: true, password: !0 };', 'bundle.js'),
            ('"Password" = "Password";', 'Localizable.strings'),
        ]
        for text, path in cases:
            with self.subTest(path=path, form=text):
                self.assertEqual(self.fields(text, path), ())
                masked = mask_nonliteral_labels(text, logical_path=path)
                self.assertEqual(len(masked), len(text))
                self.assertEqual(len(masked.encode()), len(text.encode()))
                self.assertEqual(masked.count('\n'), text.count('\n'))
        for value in ('nil', 'true', 'false', 'null', 'none', 'undefined', 'string', '%s', '!0', 'self.pwd', '<opaque synthetic>'):
            for path in ('config.py', 'config.env', 'config.json'):
                text = 'password="' + value + '"'
                with self.subTest(value=value, path=path):
                    spans = self.fields(text, path)
                    self.assertEqual([text[s.start:s.end] for s in spans], [value])
                    self.assertEqual(mask_nonliteral_labels(text, logical_path=path), text)
        for text in ('password=nil', 'password=string', 'password=opaque.synthetic.value', 'password=short', 'password=4826'):
            self.assertEqual(len(self.fields(text, 'secrets.env')), 1)
    def test_code_context_does_not_leak_between_history_lines(self):
        text = 'A user asks if this works.\npassword=opaque.synthetic.value'
        self.assertEqual(len(self.fields(text, 'history.jsonl')), 1)
        self.assertEqual(mask_nonliteral_labels(text, logical_path='history.jsonl'), text)
    def test_mixed_declaration_and_real_literal_same_line(self):
        text = 'func a(refreshToken: String?) { password="synthetic body credential" }'
        spans = self.fields(text, 'Auth.swift')
        self.assertEqual([text[s.start:s.end] for s in spans], ['synthetic body credential'])
    def test_nested_accounts_all_seven_precise_spans(self):
        values = ['synthetic-account-' + str(i) for i in range(7)]
        text = json.dumps({'accounts':[{'password':v} for v in values]})
        spans = self.fields(text, 'accounts.json')
        self.assertEqual([text[s.start:s.end] for s in spans], values)
        self.assertEqual(len({(s.start,s.end) for s in spans}), 7)
    def test_localization_identity_needs_file_type_and_complete_mapping(self):
        self.assertTrue(self.fields('"Password" = "Password";', 'config.txt'))
        self.assertTrue(self.fields('"Password" = "synthetic-account";', 'Localizable.strings'))
    def test_kube_private_key_data_is_a_private_role(self):
        text = 'client-key-data: ' + base64.b64encode(b'-----BEGIN PRIVATE KEY-----\n' + TOKEN.encode() * 4 + b'\n-----END PRIVATE KEY-----').decode()
        spans = self.fields(text, '.kube/config')
        self.assertEqual([s.rule for s in spans], ['credential-private-key'])
        self.assertEqual(text[spans[0].start:spans[0].end], text.split(': ',1)[1])


class ArtifactContextTests(unittest.TestCase):
    def test_public_key_requires_structure_and_extension_manifest_schema(self):
        key = public_spki()
        self.assertTrue(is_rsa_public_spki(key))
        self.assertFalse(is_rsa_public_spki(base64.b64encode(b'not DER private secret ' + TOKEN.encode()).decode()))
        self.assertFalse(is_rsa_public_spki(key[:-4] + 'AAAA'))
        manifest = json.dumps({'manifest_version':3,'name':'Synthetic extension','version':'1.0','key':key,'api_key':TOKEN})
        context = inspect_artifact(manifest)
        masked = mask_artifact_labels(manifest, context)
        self.assertNotIn(key, masked)
        self.assertIn(TOKEN, masked)
        self.assertEqual(len(masked.encode()), len(manifest.encode()))
        ordinary = json.dumps({'key':key})
        self.assertEqual(mask_artifact_labels(ordinary, inspect_artifact(ordinary)), ordinary)
        private = base64.b64encode(der(0x30, der(2,b'\0') + der(0x30,bytes.fromhex('06092a864886f70d0101010500')) + der(4,TOKEN.encode()*4))).decode()
        self.assertFalse(is_rsa_public_spki(private))
    def test_xml_dictionary_tag_is_structural_but_password_value_is_not(self):
        text = plist('<key>' + HEX + '</key><string>public</string><key>password</key><string>' + TOKEN + '</string>')
        context = inspect_artifact(text)
        masked = mask_artifact_labels(text,context)
        self.assertNotIn('<key>', masked)
        self.assertIn(HEX, masked)
        self.assertIn(TOKEN, masked)
        spans = scan_fields(text,CredentialDetector().pack)
        self.assertEqual([text[s.start:s.end] for s in spans], [TOKEN])
        malformed = text.replace('</plist>', '')
        self.assertEqual(inspect_artifact(malformed).masks, ())
    def test_json_localization_role_preserves_other_fields_and_token_bytes(self):
        text = json.dumps({'localizationKey':TOKEN, 'api_key':TOKEN})
        masked = mask_artifact_labels(text, inspect_artifact(text))
        self.assertNotIn('localizationKey',masked)
        self.assertIn('api_key',masked)
        self.assertEqual(masked.count(TOKEN),2)
        duplicate = '{"localizationKey":"one","localizationKey":"two"}'
        self.assertEqual(inspect_artifact(duplicate).masks, ())
    def test_encoded_binary_review_lines_exclude_mixed_and_text_data(self):
        head = base64.b64encode(b'bplist00x').decode()
        square = 'EAAA' + (TOKEN * 2)[:60]
        text = plist('<key>payload</key><data>\n' + head + '\n' + square + '\n</data>')
        self.assertEqual(inspect_artifact(text).binary_lines, ((2,3),))
        mixed = plist('<key>payload</key><data>' + head + square + '</data><key>password</key><string>' + TOKEN + '</string>')
        self.assertEqual(inspect_artifact(mixed).binary_lines, ())
        encoded = base64.b64encode(('password=' + TOKEN).encode()).decode()
        textual = plist('<key>password</key><data>\n' + encoded + '\n</data>')
        self.assertEqual(inspect_artifact(textual).binary_lines, ())
        self.assertTrue(scan_fields(textual,CredentialDetector().pack))


class NativeObservedRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('LEAKGUARD_GITLEAKS')
        if not cls.binary:raise unittest.SkipTest('pinned Gitleaks required')
    def detect(self, text, path='fixture.txt', **kwargs):
        return backends.detect(text, binary=self.binary, logical_path=path, **kwargs)
    def test_sourcegraph_prefixes_and_local_legacy(self):
        for token in ('sgp_' + HEX, 'sgp_local_' + HEX, 'sgp_' + HEX[:16] + '_' + HEX):
            self.assertIn('sourcegraph-access-token', {f.rule for f in self.detect(token)})
        self.assertNotIn('sourcegraph-access-token', {f.rule for f in self.detect(json.dumps({'sourcegraph':'https://example.invalid','sha':HEX}))})
        for text in ('SOURCEGRAPH_ACCESS_TOKEN="' + HEX + '"', 'sourcegraph: {token: "' + HEX + '"}'):
            self.assertIn('sourcegraph-access-token', {f.rule for f in self.detect(text)})
    def test_syntax_negative_pairs_and_literal_controls(self):
        for text,path in [('password: string;','types.d.ts'),('password = nil','config.rb'),('pwd=self.pwd','zipfile.py'),('def a(pwd=None):','zipfile.py'),('password == "synthetic"','config.rb'),('password:%s','config.py'),('Password: <type your password>','manual.txt'),('const opts={password:true,password:!0};','bundle.js'),('"Password" = "Password";','Localizable.strings')]:
            with self.subTest(form=text):
                self.assertNotIn('literal-password',{f.rule for f in self.detect(text,path)})
        for value in ('nil','true','null','none','undefined','string','%s','!0','4826'):
            self.assertIn('literal-password',{f.rule for f in self.detect('password="' + value + '"','config.py')})
    def test_manifest_and_localization_structures_with_sibling_secret(self):
        key = public_spki()
        for text in (json.dumps({'manifest_version':3,'name':'Synthetic','version':'1','key':key}),json.dumps({'localizationKey':TOKEN}),plist('<key>' + HEX + '</key><true/>')):
            with self.subTest(kind=text[:30]):
                self.assertNotIn('generic-api-key',{f.rule for f in self.detect(text)})
        manifest = json.dumps({'manifest_version':3,'name':'Synthetic','version':'1','key':key,'api_key':TOKEN})
        self.assertIn('generic-api-key',{f.rule for f in self.detect(manifest)})
        self.assertIn('generic-api-key',{f.rule for f in self.detect(json.dumps({'key':TOKEN}))})
    def test_square_binary_fragment_is_retained_review_and_real_token_blocks(self):
        head = base64.b64encode(b'bplist00x').decode();square='EAAA'+(TOKEN*2)[:60]
        text=plist('<key>payload</key><data>\n'+head+'\n'+square+'\n</data>')
        rows=[f for f in self.detect(text) if f.rule=='square-access-token']
        self.assertEqual([f.severity for f in rows],['review'])
        self.assertEqual(rows[0].start_line,3)
        self.assertEqual([f.severity for f in self.detect(square) if f.rule=='square-access-token'],['block'])
        mixed=plist('<key>payload</key><data>'+head+square+'</data><key>password</key><string>'+TOKEN+'</string>')
        self.assertTrue(all(f.severity=='block' for f in self.detect(mixed)))
    def test_custom_native_policy_sees_admitted_unmodified_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules=Path(tmp)/'custom.toml';rules.write_text('[[rules]]\nid="synthetic-boolean"\nregex=\'password:true\'\n')
            self.assertEqual([f.rule for f in self.detect('password:true','bundle.js',rules=rules)],['synthetic-boolean'])
    def test_long_line_nearby_literal_is_retained_without_invented_offsets(self):
        text='x'*130000+'; const opts={password:!0}; password="'+TOKEN+'";'
        rows=self.detect(text,'bundle.js')
        self.assertIn('literal-password',{f.rule for f in rows})
        self.assertTrue(all(f.start_line==1 for f in rows))
        spans=scan_fields(text,CredentialDetector().pack,logical_path='bundle.js')
        self.assertEqual([text[s.start:s.end] for s in spans],[TOKEN])
