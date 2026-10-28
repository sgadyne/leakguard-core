"""Synthetic unit tests for the strict alias resource and flat-field engine."""
import json
import importlib
import types
from unittest.mock import patch
import sys
import unittest

from credential_detector.aliases import AliasPackError, load_pack, merge_packs, parse_pack
from credential_detector.engine import MAX_TEXT, MAX_VALUE, scan_fields
from credential_detector.types import CredentialSpan


def resource(entries, pack_id='test-pack'):
    return json.dumps({'schema_version': 1, 'pack_id': pack_id, 'aliases': entries}).encode()


def entry(name='password', role='password', group='common'):
    return {'name': name, 'role': role, 'group': group}


class AliasEngineTests(unittest.TestCase):
    def setUp(self):
        self.pack = parse_pack(resource([entry(), entry('api_key', 'api-key')]))

    def test_literals_offsets_and_value_free_repr(self):
        text = 'α\nPASSWORD = "x"\napi-key: abc\npassword=change-me'
        spans = scan_fields(text, self.pack)
        self.assertEqual([s.rule for s in spans], ['credential-password', 'credential-api-key', 'credential-password'])
        self.assertEqual([text[s.start:s.end] for s in spans], ['x', 'abc', 'change-me'])
        self.assertNotIn('change-me', repr(spans))
        self.assertEqual(spans[0], CredentialSpan('credential-password', text.index('x'), text.index('x') + 1))

    def test_complete_key_and_unicode_boundaries(self):
        text = 'mypassword=long\npassword_suffix=long\népassword=long\npasswordx=long\npassword=ok'
        spans = scan_fields(text, self.pack)
        self.assertEqual([text[s.start:s.end] for s in spans], ['ok'])

    def test_unicode_combining_boundary_and_unrelated_quoted_scalar(self):
        text = 'name\u0301password=demo\n{"description":"password=demo", "password":"x"}\npassword="abc"junk\npassword=y'
        spans = scan_fields(text, self.pack)
        self.assertEqual([text[s.start:s.end] for s in spans], ['x', 'y'])

    def test_arbitrary_quoted_keys_and_standalone_scalars(self):
        for key in ('météo', '_description', '123', 'description/name'):
            text = '{"' + key + '":"password=demo","password":"z"}'
            spans = scan_fields(text, self.pack)
            self.assertEqual([text[s.start:s.end] for s in spans], ['z'])
        self.assertEqual(scan_fields('"password=demo"', self.pack), ())

    def test_quoted_references_are_literals(self):
        text = '''password=$VAR
password=${VAR}
password={{VAR}}
password=<VAR>
password=os.getenv("VAR")
password=os.environ['VAR']
password=getenv('VAR')
password=null
password=~
password="${VAR}"
password="{{VAR}}"
password="<VAR>"
password="$VAR"
password="prefix-${VAR}"
password='os.getenv("VAR")'
password="null"
'''
        spans = scan_fields(text, self.pack)
        self.assertEqual([text[s.start:s.end] for s in spans], ['$VAR', 'prefix-${VAR}', 'os.getenv("VAR")', 'null'])

    def test_malformed_empty_and_multiple_fields(self):
        text = '{"password":"", "api_key":"abc", "password":"z\\"q"}\npassword="unterminated\npassword=x'
        spans = scan_fields(text, self.pack)
        self.assertEqual([text[s.start:s.end] for s in spans], ['abc', 'z\\"q', 'x'])

    def test_conflicting_aliases_and_ids_fail_closed(self):
        with self.assertRaises(AliasPackError):
            parse_pack(resource([entry('api-key'), entry('api_key', 'api-key')]))
        with self.assertRaises(AliasPackError):
            merge_packs(self.pack, parse_pack(resource([entry('password')], 'different')))
        with self.assertRaises(AliasPackError):
            merge_packs(self.pack, parse_pack(resource([entry('another')], 'test-pack')))

    def test_invalid_resources_are_value_free(self):
        invalid = [b'{', b'{"schema_version":1,"schema_version":1}', b'\xff',
                   resource([entry('bad/key')]), resource([entry(role='other')]),
                   resource([dict(entry(), extra='secret-synthetic')]),
                   json.dumps({'schema_version': True, 'pack_id': 'p', 'aliases': [entry()]}).encode(),
                   b' ' * 262145]
        for data in invalid:
            with self.subTest(kind=len(data)):
                with self.assertRaises(AliasPackError) as caught:
                    parse_pack(data)
                self.assertNotIn('secret-synthetic', str(caught.exception))
        for path in ('../x', '/x', 'missing.json'):
            with self.assertRaises(AliasPackError):
                load_pack('credential_detector', path)

    def test_wrapper_dispatches_extracted_text_and_preserves_offsets(self):
        from leakguard_core.plugins import detect
        fake_http = types.ModuleType('credential_detector.http')
        fake_http.scan_http = lambda text: ()
        # Exercise the wrapper independently of the separately owned HTTP lane.
        with patch.dict(sys.modules, {'credential_detector.http': fake_http}):
            sys.modules.pop('credential_detector.plugin', None)
            plugin = importlib.import_module('credential_detector.plugin')
            with patch.object(plugin, 'load_packs', return_value=self.pack):
                instance = plugin.CredentialDetector()
            class Adapter:
                manifest = plugin.MANIFEST
                def detect(self, text, context, **kwargs):
                    return instance.detect(text, context)
            text = 'α\npassword=x'
            findings = list(detect([Adapter()], text, 'fixture.pdf', 'page-1', format_id='pdf-text'))
            self.assertEqual(len(findings), 1)
            self.assertEqual((findings[0].line, findings[0].analysis.start, findings[0].analysis.end), (2, 11, 12))
            sys.modules.pop('credential_detector.plugin', None)

    def test_bounds_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'limit'):
            scan_fields('x' * (MAX_TEXT + 1), self.pack)
        with self.assertRaisesRegex(ValueError, 'limit'):
            scan_fields('password=' + 'x' * (MAX_VALUE + 1), self.pack)
        with self.assertRaisesRegex(ValueError, 'limit'):
            scan_fields('password="' + 'x' * (MAX_VALUE + 1) + '"', self.pack)

    def test_long_unrelated_fields_do_not_abort_credential_inspection(self):
        # Source maps and CSS data URIs routinely exceed the credential-value
        # bound. Unknown fields remain bounded by MAX_TEXT and are consumed as
        # one scalar, including alias-looking text inside an unrelated quote.
        for quoted in (False, True):
            value = 'x' * (MAX_VALUE + 1) + ' password=inside-unrelated-scalar'
            scalar = '"' + value + '"' if quoted else value
            text = 'unrelated=' + scalar + '\npassword=visible-synthetic-control\n'
            spans = scan_fields(text, self.pack)
            self.assertEqual([text[s.start:s.end] for s in spans], ['visible-synthetic-control'])


if __name__ == '__main__':
    unittest.main()

class BetaQualityRegressions(unittest.TestCase):
    def test_masked_operational_shapes_and_code_controls(self):
        from credential_detector.plugin import CredentialDetector
        from credential_detector.engine import scan_contextual
        pack=CredentialDetector().pack
        cases=[('refresh_token="synthetic_refresh_value_0123456789"','credential-access-token'),('ACME_BEARER_TOKENS_JSON="{\\"operator\\":\\"synthetic-token\\"}"','credential-access-token'),('ACME_OPERATOR_PASSWORD=synthetic_password_value','credential-password'),('ACME_FIRST_PASSWORD=synthetic_password_value','credential-password'),('OAUTH2_PROXY_CLIENT_SECRET=synthetic_secret','credential-client-secret'),('ACME_CUSTOM_PIN=482619','credential-password')]
        for text,rule in cases:
            with self.subTest(shape=text.split('=')[0]):self.assertIn(rule,[s.rule for s in scan_fields(text,pack)])
        for text in ['password=getpass.getpass("Enter password: ")','password=make_password()','password := randomPassword()','password=os.environ["VALUE"]']:
            with self.subTest(expression=text):self.assertEqual(scan_fields(text,pack),())
        for text in ['My mailbox password is synthetic-only-value.','Mailbox credential\nsynthetic-only-value','Wallet recovery words: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']:
            self.assertTrue(scan_contextual(text))
