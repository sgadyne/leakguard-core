import json
from pathlib import Path

import pytest

from leakguard_buddy.backend import BuddyBackend, BuddyOperationError
from leakguard_host.errors import HostError


def backend(tmp_path):
    config = tmp_path/'config.json'
    if not config.exists(): config.write_text('{}')
    return BuddyBackend(state_dir=tmp_path/'profile', config_path=config, discovery_roots=())


def document():
    return {'version':1, 'preset':'inventory', 'overrides':{'inspection':{'max_file_bytes':4096},
            'jobs':{'reconcile':{'mode':'interval','interval_seconds':300,'daily_time':'09:00','timezone':'UTC'}}}}


def test_apply_persists_effective_config_and_jobs_across_restart(tmp_path):
    b = backend(tmp_path)
    try:
        doc = document(); preview = b.preview_scan_profile(doc)
        assert b.settings()['max_file_bytes'] != 4096
        result = b.apply_scan_profile(doc, preview['identity'])
        assert result['runtime_preflight'] == 'passed'
        assert b.settings()['max_file_bytes'] == 4096
        assert b.settings()['protection']['new_content'] == 'inventory'
        assert not b.scan_profiles()['current']['customized']
        assert json.loads((tmp_path/'config.json').read_text()) == {}
    finally: b.close()
    b = backend(tmp_path)
    try:
        assert b.settings()['max_file_bytes'] == 4096
        assert b.settings()['protection']['schedule']['interval_seconds'] == 300
        assert not b.scan_profiles()['current']['customized']
        b.save_settings({'scan_workers':1})
        assert b.scan_profiles()['current']['customized']
    finally: b.close()


def test_stale_preview_and_unavailable_capability_leave_settings_unchanged(tmp_path):
    b = backend(tmp_path)
    try:
        doc = document(); preview = b.preview_scan_profile(doc)
        b.save_settings({'scan_workers':1}); before = b.settings()
        with pytest.raises(BuddyOperationError, match='scan-profile-preview-stale'):
            b.apply_scan_profile(doc, preview['identity'])
        with pytest.raises(HostError, match='scan-profile-capability-unavailable'):
            b.preview_scan_profile({'version':1,'preset':'standard','overrides':{'jobs':{'changes':'events'}}})
        assert b.settings() == before
        assert not (b.state_dir/'scan-profile.json').exists()
    finally: b.close()


def test_failed_runtime_preflight_does_not_publish_profile(tmp_path, monkeypatch):
    import leakguard_host.scan_profiles as profiles
    b = backend(tmp_path)
    try:
        doc = {'version':1,'preset':'standard'}; preview = b.preview_scan_profile(doc); before = b.settings()
        def fail(plan): raise HostError('scan-profile-runtime-unavailable')
        monkeypatch.setattr(profiles, 'preflight', fail)
        with pytest.raises(HostError): b.apply_scan_profile(doc, preview['identity'])
        assert b.settings() == before
        assert not (b.state_dir/'scan-profile.json').exists()
    finally: b.close()


def test_failed_config_swap_restores_previous_receipt_and_protection(tmp_path, monkeypatch):
    b = backend(tmp_path)
    try:
        doc = document(); b.apply_scan_profile(doc, b.preview_scan_profile(doc)['identity'])
        path = b.state_dir/'scan-profile.json'; original = path.read_bytes(); before = b.settings()
        doc['overrides']['inspection']['max_file_bytes'] = 8000
        preview = b.preview_scan_profile(doc)
        def fail(*args, **kwargs): raise RuntimeError('synthetic swap failure')
        monkeypatch.setattr(b, '_replace_scan_config', fail)
        with pytest.raises(RuntimeError): b.apply_scan_profile(doc, preview['identity'])
        assert path.read_bytes() == original
        assert b.settings() == before
    finally: b.close()


def test_applied_profile_reaches_real_host_and_preserves_source_override(tmp_path, monkeypatch):
    from leakguard_host import HostService
    monkeypatch.setattr(HostService, 'start', lambda self: None)
    b = backend(tmp_path)
    try:
        b.observation_create('synthetic-scan-profile-passphrase')
        source = b._host.add_source(tmp_path)
        b._host.manage_source(source['id'])
        b._host.update_source(source['id'], schedule_seconds=120)
        store = b._observation_store
        doc = document(); b.apply_scan_profile(doc, b.preview_scan_profile(doc)['identity'])
        assert b._observation_store is store
        assert b._host._config.to_mapping()['max_file_bytes'] == 4096
        assert b._host._protection['new_content'] == 'inventory'
        assert b._host.sources()[0]['schedule_seconds'] == 120
        assert b.credential_status()['unlocked'] is False
    finally: b.close()


def test_failed_new_host_restores_old_job_policy_before_restart(tmp_path, monkeypatch):
    b = backend(tmp_path)
    class Host:
        def stop(self): pass
    store = object(); old_host = Host()
    b._observation_store = store; b._host = old_host
    before = b.settings()['protection']; starts = []
    def start(candidate):
        starts.append(dict(b._protection))
        if len(starts) == 1: raise RuntimeError('synthetic candidate failure')
        b._host = Host()
    monkeypatch.setattr(b, '_start_host', start)
    try:
        doc = document()
        with pytest.raises(RuntimeError): b.apply_scan_profile(doc, b.preview_scan_profile(doc)['identity'])
        assert starts[0]['new_content'] == 'inventory'
        assert starts[1] == before
        assert b.settings()['protection'] == before
    finally:
        b._host = None; b._observation_store = None; b.close()


@pytest.mark.parametrize('broken', ['missing-overlay', 'dangling-link'])
def test_corrupt_profile_overlay_fails_closed_on_restart(tmp_path, broken):
    b = backend(tmp_path); path = b.state_dir / 'scan-profile.json'; b.close()
    if broken == 'dangling-link': path.symlink_to(tmp_path / 'absent')
    else: path.write_text(json.dumps({'document':document()}))
    with pytest.raises(BuddyOperationError, match='scan-profile-record-invalid'): backend(tmp_path)
