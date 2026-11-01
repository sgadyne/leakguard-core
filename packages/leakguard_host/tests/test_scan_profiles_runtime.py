"""Opt-in installed-wheel check; use the release's actual Gitleaks executable."""
import os
import sys

import pytest

from leakguard_core.api import ScanConfig, Scanner, ScanPolicy, ScanLimits
from leakguard_core.models import BytesInput
from leakguard_core.scan_store import MemoryScanStore
from leakguard_host.scan_profiles import resolve, preflight


@pytest.mark.skipif(not os.environ.get('LEAKGUARD_PROFILE_RUNTIME_CHECK'), reason='requires matching installed wheels and explicit Gitleaks path')
def test_configured_aliases_execute_in_real_supervised_workers(tmp_path, monkeypatch):
    monkeypatch.setenv('LEAKGUARD_STATE_DIR', str(tmp_path / 'state'))
    plan = resolve({'version':1, 'preset':'standard', 'overrides':{'packs':['team']},
                    'packs':[{'id':'team', 'version':1, 'plugins':[{
                        'module':'credential_detector.plugin', 'options':{'aliases':['corpPassword:password','corpSession:access-token']}}]}]},
                   base_config={'gitleaks_executable':os.environ['LEAKGUARD_GITLEAKS'],
                                'worker_policy':'supervised-alpha' if sys.platform == 'darwin' else 'strict'})
    preflight(plan)
    marker = 'profile-synthetic-positive-139'
    positive = f'corpPassword="{marker}"\ncorpSession="profile-synthetic-session-271"\n'.encode()
    negative = b'myCorpPasswordSuffix="profile-synthetic-negative-911"\ncorpPassword=$ENV_REFERENCE\n'
    config = ScanConfig.from_mapping(plan.config)
    with Scanner.open(config=config, store=MemoryScanStore(config=plan.config)) as scanner:
        report = scanner.scan([BytesInput(positive,'positive.env'), BytesInput(negative,'negative.env')],
                              policy=ScanPolicy.inventory(), limits=ScanLimits(45,2), use_cache=False)
    assert report.coverage.required_complete
    rows = {row.source.path:row for row in report.results}
    rules = {finding.rule for finding in rows['positive.env'].findings if finding.detector_id == 'plugin-credential-detector'}
    assert {'credential-password','credential-access-token'} <= rules
    assert not rows['negative.env'].findings
    for value in (marker, 'profile-synthetic-session-271', 'profile-synthetic-negative-911'):
        assert value not in report.to_json()
