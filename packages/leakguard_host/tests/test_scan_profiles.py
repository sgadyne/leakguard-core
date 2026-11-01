import json
import os
from copy import deepcopy

import pytest

from leakguard_host.errors import HostError
from leakguard_host.scan_profiles import resolve, read_document, catalog
from leakguard_host.protection import defaults


def custom():
    return {'version': 1, 'preset': 'engineering', 'presets': [
        {'id': 'engineering', 'version': 2, 'extends': 'standard', 'packs': ['team'],
         'jobs': {'reconcile': {'mode': 'interval', 'interval_seconds': 300, 'daily_time': '09:00', 'timezone': 'UTC'}}}],
        'packs': [{'id': 'team', 'version': 1, 'plugins': [{'module': 'credential_detector.plugin',
                    'options': {'aliases': ['corpPassword:password']}}]}]}


def test_inheritance_composes_real_config_and_preserves_existing_choices():
    doc = custom(); before = deepcopy(doc)
    base = {'plugins': [{'module': 'presidio_detector.plugin', 'options': {'recognizer-modules': ['acme.rules:build'], 'score-threshold': '0.8'}}],
            'exclude_roots': ['/synthetic-excluded'], 'worker_policy': 'supervised-alpha'}
    plan = resolve(doc, base_config=base)
    assert doc == before
    assert plan.protection['schedule']['interval_seconds'] == 300
    assert plan.config['exclude_roots'] == ['/synthetic-excluded']
    plugin = next(x for x in plan.config['plugins'] if x['module'] == 'presidio_detector.plugin')
    assert plugin['options']['score-threshold'] == '0.8'
    assert 'acme.rules:build' in plugin['options']['recognizer-modules']
    assert 'jose_recognizers.plugin:build_recognizers' in plugin['options']['recognizer-modules']
    assert plan.provenance['jobs.reconcile'] == 'engineering@2'
    assert next(x for x in plan.config['plugins'] if x['module'] == 'credential_detector.plugin')['options']['aliases'] == ['corpPassword:password']


def test_resolve_is_inert_and_preview_does_not_echo_option_values(monkeypatch):
    import importlib
    monkeypatch.setattr(importlib, 'import_module', lambda *a, **k: pytest.fail('plugin import in preview'))
    doc = custom(); doc['packs'][0]['plugins'].append({'module': 'not_installed.plugin', 'options': {'private-option': 'SYNTHETIC_PRIVATE_VALUE'}})
    plan = resolve(doc)
    assert 'SYNTHETIC_PRIVATE_VALUE' not in json.dumps(plan.preview())
    assert 'runtime_preflight' in plan.preview()


@pytest.mark.parametrize('jobs', [{'changes': 'events'}, {'deep': 'archives'}, {'access': 'audit'}])
def test_missing_capability_never_falls_back(jobs):
    with pytest.raises(HostError, match='scan-profile-capability-unavailable'):
        resolve({'version': 1, 'preset': 'standard', 'overrides': {'jobs': jobs}})


def test_inventory_does_not_enable_detectors_or_mutate_scope():
    protection = defaults(); protection['automatic_this_mac'] = False; protection['exclusions'] = ['/synthetic']
    plan = resolve({'version': 1, 'preset': 'inventory'}, base_protection=protection)
    assert plan.config['plugins'] == []
    assert plan.protection['new_content'] == 'inventory'
    assert not plan.protection['automatic_this_mac']
    assert plan.protection['exclusions'] == ['/synthetic']


def test_identity_changes_with_options_budgets_and_jobs_and_is_repeatable():
    doc = custom(); original = resolve(doc).identity
    assert resolve(doc).identity == original
    for change in ({'inspection': {'max_file_bytes': 1000}}, {'jobs': {'reconcile': {'mode': 'interval', 'interval_seconds': 600, 'daily_time': '09:00', 'timezone': 'UTC'}}}):
        candidate = deepcopy(doc); candidate['overrides'] = change
        assert resolve(candidate).identity != original
    doc['packs'][0]['plugins'][0]['options']['aliases'] = ['corpToken:access-token']
    assert resolve(doc).identity != original


def test_trusted_caller_ceilings_cannot_be_overridden():
    with pytest.raises(HostError, match='scan-profile-policy-limit'):
        resolve(custom(), ceilings={'max_file_bytes': 1024})
    doc = custom(); doc['overrides'] = {'inspection': {'max_file_bytes': 1024}}
    assert resolve(doc, ceilings={'max_file_bytes': 1024}).config['max_file_bytes'] == 1024


def test_ambiguous_component_packs_and_cycles_rejected():
    doc = custom(); second = deepcopy(doc['packs'][0]); second['id'] = 'other'; doc['packs'].append(second); doc['presets'][0]['packs'].append('other')
    with pytest.raises(HostError, match='scan-profile-component-conflict'): resolve(doc)
    doc = custom(); doc['presets'][0]['extends'] = 'engineering'
    with pytest.raises(HostError, match='scan-profile-inheritance-cycle'): resolve(doc)


@pytest.mark.parametrize('bad', [
    {'version': True, 'preset': 'standard'}, {'version': 1, 'preset': 'standard', 'command': 'ignored'},
    {'version': 1, 'preset': 'standard', 'overrides': {'inspection': {'mode': []}}},
    {'version': 1, 'preset': 'standard', 'overrides': {'inspection': {'max_file_bytes': True}}},
    {'version': 1, 'preset': 'standard', 'overrides': {'jobs': {'changes': []}}},
    {'version': 1, 'preset': 'unknown'},
])
def test_schema_rejects_unknown_fields_and_wrong_types(bad):
    with pytest.raises(HostError): resolve(bad)


def test_reader_rejects_duplicate_keys_and_symlinks(tmp_path):
    p = tmp_path/'profile.json'; p.write_text('{"version":1,"preset":"standard","preset":"inventory"}')
    with pytest.raises(HostError): read_document(p)
    p.write_text(json.dumps(custom())); link = tmp_path/'link.json'; link.symlink_to(p)
    with pytest.raises(HostError): read_document(link)
    assert resolve(read_document(p)).document['preset'] == 'engineering'


def test_cli_export_is_private_and_never_overwrites(tmp_path, capsys):
    from leakguard_host.cli import main
    doc = tmp_path/'input.json'; doc.write_text(json.dumps(custom())); out = tmp_path/'export'
    argv = ['scan-profile', 'export', '--document', str(doc), '--output-directory', str(out)]
    assert main(argv) == 0
    assert json.loads((out/'config.json').read_text())['plugins']
    assert json.loads((out/'protection-settings.json').read_text())['schedule']['interval_seconds'] == 300
    if os.name == 'posix':
        assert out.stat().st_mode & 0o777 == 0o700
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in out.iterdir())
    before = (out/'config.json').read_bytes()
    assert main(argv) == 2
    assert (out/'config.json').read_bytes() == before


def test_catalog_is_detached():
    data = catalog(); data['presets'][0]['inspection']['mode'] = 'inventory'
    assert resolve({'version': 1, 'preset': 'standard'}).protection['new_content'] == 'inspect'


def test_reapplication_is_idempotent_including_named_omissions():
    doc = custom()
    doc['packs'][0]['omissions'] = [{'id':'team-optional', 'selector':{'kind':'format','value':'pdf'}, 'reason_code':'optional-format'}]
    first = resolve(doc)
    again = resolve(doc, base_config=first.config, base_protection=first.protection)
    assert first.identity == again.identity
    assert first.config == again.config
    doc['packs'][0]['omissions'][0]['selector']['value'] = 'rtf'
    changed = resolve(doc, base_config=first.config, base_protection=first.protection)
    assert len(changed.config['omissions']) == 1
    assert changed.config['omissions'][0]['selector']['value'] == 'rtf'


def test_resolved_protection_is_detached_from_callers_state():
    protection = defaults(); protection['exclusions'] = ['/synthetic']
    plan = resolve({'version':1,'preset':'inventory'}, base_protection=protection)
    plan.protection['exclusions'].append('/other')
    assert protection['exclusions'] == ['/synthetic']
