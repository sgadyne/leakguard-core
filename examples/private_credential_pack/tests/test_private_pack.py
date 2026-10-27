"""Exercise the private detector and its explicit dependency/resource boundary."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from credential_detector.aliases import AliasPackError
from leakguard_core.plugins import DetectionContext
from private_credential_pack import MANIFEST, create_plugin
from private_credential_pack import plugin

CONTEXT = DetectionContext(logical_path='synthetic.txt', part_id='text', format_id='text')


def test_private_detector_emits_original_offsets_and_keeps_input():
    text = 'prefix\nacme_deploy_key="x"\n'
    before = text
    findings = list(create_plugin({}).detect(text, CONTEXT))
    assert text == before
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule, finding.line, finding.severity) == ('credential-api-key', 2, 'block')
    assert text[finding.analysis.start:finding.analysis.end] == 'x'
    assert list(create_plugin({}).detect('prefixacme_deploy_key_suffix="x"', CONTEXT)) == []
    assert list(create_plugin({}).detect('acme_deploy_key=$DEPLOY_KEY', CONTEXT)) == []
    assert len(list(create_plugin({}).detect('acme_deploy_key="$DEPLOY_KEY"', CONTEXT))) == 1


def test_fail_closed_missing_resource_and_invalid_options(monkeypatch):
    def missing(*_args):
        raise AliasPackError('alias resource unavailable')
    monkeypatch.setattr(plugin, 'load_pack', missing)
    with pytest.raises(AliasPackError, match='alias resource unavailable'):
        create_plugin({})
    with pytest.raises(ValueError, match='invalid options'):
        create_plugin({'unexpected': 'value'})


def test_manifest_declares_dependencies_and_unknown_external_state():
    assert {d.name for d in MANIFEST.dependencies} == {
        'leakguard-core', 'leakguard-credential-detector', 'leakguard-private-credential-example'}
    assert MANIFEST.external_state == 'unknown'


def test_missing_engine_is_not_silently_ignored():
    # Isolated interpreter with only core and this example on sys.path: the
    # engine distribution is intentionally absent even if installed in pytest's venv.
    root = Path(__file__).resolve().parents[3]
    private_src = root / 'examples/private_credential_pack/src'
    core_src = root / 'src'
    script = ('import sys; sys.path[:0] = ' + repr([str(private_src), str(core_src)]) +
              '; import private_credential_pack')
    env = dict(os.environ)
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script],
                            capture_output=True, text=True, env=env, check=False)
    assert result.returncode != 0
    assert "No module named 'credential_detector'" in result.stderr
