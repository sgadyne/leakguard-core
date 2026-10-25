"""Maintained fixed-argv script detector using the common v2 result validator."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from ._supervision import WorkerError, run_worker, worker_environment
from .plugins import (DetectionContext, Finding, PluginError, PluginManifest, RuleSpec,
                      _loads, _validated_findings)


@dataclass(frozen=True)
class ScriptDetector:
    manifest: PluginManifest
    argv: tuple[str, ...] = field(repr=False)

    @classmethod
    def from_mapping(cls, spec):
        # Reuse configuration admission, including fixed absolute executable.
        from .settings import validate
        normalized = validate({'script_checks': [spec]})['script_checks'][0]
        manifest = PluginManifest(normalized['id'], normalized.get('implementation_version', '1'),
                                  'detector', rules=tuple(RuleSpec(item['id'], item.get('minimum_severity', 'review')) for item in normalized['rules']),
                                  deterministic=normalized.get('deterministic', True),
                                  external_state=normalized.get('external_state', 'unknown'))
        return cls(manifest, tuple(normalized['argv']))

    @property
    def identity(self):
        # Include executable and fixed file arguments (e.g. interpreter + script).
        artifacts = []
        for value in self.argv:
            path = Path(value)
            try:
                artifacts.append(hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else 'argument')
            except OSError:
                artifacts.append('unavailable')
        return hashlib.sha256(json.dumps([self.argv, artifacts], separators=(',', ':')).encode()).hexdigest()

    def detect(self, text, path, part=None, *, format_id='text', timeout=45, limits=None, cancel=None):
        if isinstance(path, DetectionContext):
            context = path
        else:
            context = DetectionContext(str(path), part or 'text', format_id)
        request = {'schema_version': 1, 'logical_path': context.logical_path,
                   'part_id': context.part_id, 'format_id': context.format_id, 'text': text}
        maximum = getattr(limits, 'max_findings', 100_000)
        try:
            with tempfile.TemporaryDirectory(prefix='leakguard-check-') as scratch:
                output = run_worker(self.argv, json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode('utf-8'),
                                    timeout=timeout, max_output_bytes=getattr(limits, 'max_ipc_bytes', 80_000_000),
                                    max_input_bytes=getattr(limits, 'max_ipc_bytes', 80_000_000),
                                    memory_bytes=getattr(limits, 'worker_memory_bytes', 512 * 1024 * 1024),
                                    env=worker_environment(), cwd=scratch, cancel=cancel)
            if output.returncode:
                raise PluginError('plugin-crashed')
            value = _loads(output.stdout)
            if type(value) is not dict or set(value) != {'schema_version', 'findings'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or type(value['findings']) is not list:
                raise PluginError('detector-output-invalid')
            findings = []
            for item in value['findings']:
                if type(item) is not dict or set(item) != {'rule', 'line', 'severity'}:
                    raise PluginError('detector-output-invalid')
                findings.append(Finding(**item))
            return tuple(_validated_findings(findings, text, self.manifest, maximum))
        except WorkerError as error:
            raise PluginError({'worker-timeout': 'plugin-timeout', 'worker-output-limit': 'detector-output-limit',
                               'resource-bound-unavailable': 'resource-bound-unavailable', 'cancelled': 'cancelled'}.get(error.code, 'plugin-crashed')) from None
        except PluginError:
            raise
        except Exception:
            raise PluginError('detector-output-invalid') from None
