"""Exercise the private detector and its explicit dependency/resource boundary."""
import subprocess
import sys

import pytest

from credential_detector.aliases import AliasPackError
from leakguard_core.plugins import DetectionContext, close, detect, load
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


def test_extracted_part_dispatch_preserves_original_offsets():
    # Exercise the actual worker-backed dispatcher, not just the detector method.
    text = 'é prefix\nacme_deploy_key="x"\n'
    policy = 'supervised-alpha' if sys.platform == 'darwin' else 'strict'
    plugins = load([{'module': 'private_credential_pack.plugin'}], worker_policy=policy)
    try:
        findings = list(detect(plugins, text, 'synthetic.pdf', 'page-1',
                               format_id='pdf-text', worker_policy=policy))
    finally:
        close(plugins)
    assert len(findings) == 1
    finding = findings[0]
    start = text.index('"x"') + 1
    assert (finding.rule, finding.line, finding.severity) == ('credential-api-key', 2, 'block')
    assert (finding.analysis.start, finding.analysis.end) == (start, start + 1)
    assert text == 'é prefix\nacme_deploy_key="x"\n'


def test_missing_engine_is_not_silently_ignored():
    # Block the dependency in a fresh interpreter while importing the installed
    # private package. No checkout paths are added to the interpreter.
    script = """
import importlib.abc
import sys
class MissingEngine(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'credential_detector':
            raise ModuleNotFoundError("No module named 'credential_detector'", name=fullname)
sys.meta_path.insert(0, MissingEngine())
import private_credential_pack
"""
    result = subprocess.run([sys.executable, '-I', '-c', script],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "No module named 'credential_detector'" in result.stderr
