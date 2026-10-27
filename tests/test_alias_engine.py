"""Synthetic unit tests for the strict alias resource and flat-field engine."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'plugins/credential_detector/src'))

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

    def test_bounds_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'limit'):
            scan_fields('x' * (MAX_TEXT + 1), self.pack)
        with self.assertRaisesRegex(ValueError, 'limit'):
            scan_fields('password=' + 'x' * (MAX_VALUE + 1), self.pack)
        with self.assertRaisesRegex(ValueError, 'limit'):
            scan_fields('password="' + 'x' * (MAX_VALUE + 1) + '"', self.pack)


if __name__ == '__main__':
    unittest.main()
