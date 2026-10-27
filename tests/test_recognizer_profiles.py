import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from leakguard_core import recognizer_profiles as profiles, settings


class RecognizerProfileTests(unittest.TestCase):
    def test_core_defaults_remain_optional_and_all_native_profiles_enable_jose(self):
        self.assertEqual(settings.validate({})['plugins'], [])
        for name in profiles.PROFILES:
            config = profiles.compose(name)
            options = config['plugins'][0]['options']
            self.assertEqual(config['detection_profile'], name)
            self.assertTrue(set(profiles.JOSE_ENTITIES) <= set(options['entities']))
            self.assertIn(profiles.JOSE_FACTORY, options['recognizer-modules'])
            self.assertEqual(options['block-entities'], [])
            self.assertEqual(options['ner-mode'], 'pattern-only')
            self.assertEqual(options['presets'], [] if name == 'credentials' else ['financial', 'identity'])
            self.assertEqual([spec for spec in config['plugins'] if spec['module'] == profiles.CREDENTIAL_MODULE],
                             [{'module': profiles.CREDENTIAL_MODULE, 'options': {}}])

    def test_composition_preserves_firm_factory_options_without_mutating_base(self):
        options = {'entities': ['FIRM_ACCOUNT_ID'],
                   'recognizer-modules': ['firm_presidio_recognizer.plugin:build_recognizers'],
                   'recognizer-options': '{"firm_presidio_recognizer.plugin:build_recognizers":{"prefix":"FIRM-DEMO"}}',
                   'score-threshold': '0.7', 'block-entities': ['FIRM_ACCOUNT_ID']}
        base = {'plugins': [{'module': 'presidio_detector.plugin', 'options': options}]}
        before = json.dumps(base, sort_keys=True)
        config = profiles.compose('firm', base)
        actual = config['plugins'][0]['options']
        self.assertEqual(json.dumps(base, sort_keys=True), before)
        for key in ('recognizer-options', 'score-threshold', 'block-entities'):
            self.assertEqual(actual[key], options[key])
        self.assertEqual(actual['recognizer-modules'][0], options['recognizer-modules'][0])
        self.assertEqual(profiles.compose('firm', config), config)

    def test_existing_implicit_default_pii_is_retained(self):
        config = profiles.compose('credentials', {'plugins': [{'module': 'presidio_detector.plugin'}]})
        self.assertTrue(set(profiles.PII_ENTITIES) <= set(config['plugins'][0]['options']['entities']))

    def test_healthcare_is_explicit_and_credentials_rejects_it(self):
        config = profiles.compose('sensitive', healthcare=True)
        self.assertIn('healthcare', config['plugins'][0]['options']['presets'])
        with self.assertRaises(settings.ConfigurationError):
            profiles.compose('credentials', healthcare=True)

    def test_ambiguous_adapters_and_invalid_lists_fail_safely(self):
        for plugins in ([{'module': 'presidio_detector.plugin'}] * 2,
                        [{'module': profiles.CREDENTIAL_MODULE}] * 2,
                        [{'module': 'presidio_detector.plugin', 'options': {'entities': 'private-value'}}]):
            with self.assertRaises(settings.ConfigurationError) as error:
                profiles.compose('firm', {'plugins': plugins})
            self.assertNotIn('private-value', str(error.exception))

    def test_existing_private_plugins_and_credential_spec_are_preserved(self):
        private = {'module': 'private_credential_pack.plugin', 'options': {'firm-setting': 'retained'}}
        credential = {'module': profiles.CREDENTIAL_MODULE, 'options': {}}
        base = {'plugins': [private, credential], 'scan_workers': 1, 'review_only_rules': ['jwt']}
        config = profiles.compose('firm', base)
        self.assertEqual(config['plugins'][:2], [private, credential])
        self.assertEqual(config['scan_workers'], 1)
        self.assertEqual(config['review_only_rules'], ['jwt'])
        self.assertEqual(profiles.compose('firm', config), config)
        self.assertEqual(base['plugins'], [private, credential])

    def test_command_creates_private_config_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'profile.json'
            args = ['--profile', 'credentials', '--output', str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(profiles.main(args), 0)
            config = settings.read_config(output)
            self.assertEqual(config['detection_profile'], 'credentials')
            original = output.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                profiles.main(args)
            self.assertEqual(output.read_bytes(), original)
