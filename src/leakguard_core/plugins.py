"""Explicit trusted extension SDK and supervised v1/v2 adapters.

There is no discovery or download. Supervision bounds crashes/resources; plugins
still run trusted Python with the scanner account's filesystem/network rights.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import importlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Protocol

from ._supervision import WorkerError, run_worker, worker_environment
from ._python import core_command, extension_paths
from .models import AnalysisMetadata
from .extraction import (Extraction, ExtractedPart, ExtractionContext, ExtractionLimits)

API_VERSION = 1
CORE_API_MINOR = 0
_TOKEN = re.compile(r'[a-z][a-z0-9-]{0,79}\Z')
_MODULE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z')
_EXTRACT_ISSUES = frozenset({'encrypted', 'no-text', 'unsupported-format', 'decode-failed',
                            'extract-failed', 'dependency-unavailable', 'extract-output-limit',
                            'extract-part-limit', 'extract-timeout'})


class PluginError(RuntimeError):
    def __init__(self, code='plugin-invalid'):
        self.code = code if code in {'plugin-invalid', 'plugin-timeout', 'plugin-crashed',
                                   'detector-output-invalid', 'detector-output-limit',
                                   'extract-output-limit', 'extract-part-limit',
                                   'resource-bound-unavailable', 'worker-memory-limit', 'cancelled', 'encrypted', 'no-text',
                                   'unsupported-format', 'decode-failed', 'extract-failed',
                                   'extract-timeout',
                                   'dependency-unavailable'} else 'plugin-invalid'
        super().__init__(self.code)


@dataclass(frozen=True)
class Finding:
    rule: str
    line: int
    severity: str = 'review'


@dataclass(frozen=True)
class NewFinding(Finding):
    """Opt-in result_schema=2; offsets are Unicode codepoints, end exclusive."""
    analysis: AnalysisMetadata | None = None


@dataclass(frozen=True)
class DetectionContext:
    logical_path: str
    part_id: str
    format_id: str


@dataclass(frozen=True)
class RuleSpec:
    id: str
    minimum_severity: str = 'review'

    def __post_init__(self):
        if type(self.id) is not str or not _TOKEN.fullmatch(self.id) or self.minimum_severity not in {'block', 'review'}:
            raise PluginError()


@dataclass(frozen=True)
class DistributionSpec:
    name: str

    def __post_init__(self):
        if type(self.name) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', self.name):
            raise PluginError()


@dataclass(frozen=True)
class OptionSpec:
    name: str
    kind: str
    required: bool = False
    default: object = field(default=None, repr=False)
    min_value: int | None = None
    max_value: int | None = None
    max_length: int = 4096
    choices: tuple[str, ...] = ()

    def __post_init__(self):
        if (type(self.name) is not str or not _TOKEN.fullmatch(self.name)
                or self.kind not in {'bool', 'int', 'string', 'enum', 'list'}
                or type(self.required) is not bool or type(self.max_length) is not int
                or not 1 <= self.max_length <= 1_000_000 or type(self.choices) is not tuple
                or any(type(x) is not str or len(x) > 4096 for x in self.choices)
                or any(value is not None and type(value) is not int for value in (self.min_value, self.max_value))):
            raise PluginError()
        if self.min_value is not None and self.max_value is not None and self.min_value > self.max_value:
            raise PluginError()
        if self.kind == 'enum' and not self.choices:
            raise PluginError()


@dataclass(frozen=True)
class OptionSchema:
    fields: tuple[OptionSpec, ...] = ()

    def __post_init__(self):
        if (type(self.fields) is not tuple or len(self.fields) > 100
                or any(type(x) is not OptionSpec for x in self.fields)
                or len({x.name for x in self.fields}) != len(self.fields)):
            raise PluginError()


@dataclass(frozen=True)
class PluginManifest:
    id: str
    implementation_version: str
    kind: str
    rules: tuple[RuleSpec, ...] = ()
    formats: tuple[str, ...] = ()
    part_kinds: tuple[str, ...] = ()
    options_schema: OptionSchema = OptionSchema()
    dependencies: tuple[DistributionSpec, ...] = ()
    deterministic: bool = True
    external_state: str = 'unknown'
    api_major: int = 2
    api_minor: int = 0
    requires_core: tuple[int, int] = (0, 0)
    worker_lifetime: str = 'request'
    result_schema: int = 1

    def __post_init__(self):
        if (type(self.id) is not str or not _TOKEN.fullmatch(self.id)
                or type(self.implementation_version) is not str or not 1 <= len(self.implementation_version) <= 200
                or self.kind not in {'detector', 'extractor'}
                or self.worker_lifetime not in {'request', 'session'}
                or type(self.result_schema) is not int or self.result_schema not in {1, 2}
                or type(self.rules) is not tuple or any(type(x) is not RuleSpec for x in self.rules)
                or len(self.rules) > 10_000 or len({x.id for x in self.rules}) != len(self.rules)
                or type(self.options_schema) is not OptionSchema
                or type(self.dependencies) is not tuple or any(type(x) is not DistributionSpec for x in self.dependencies)
                or type(self.deterministic) is not bool or self.external_state not in {'none', 'declared', 'unknown'}
                or type(self.api_major) is not int or self.api_major != 2
                or type(self.api_minor) is not int or self.api_minor != 0
                or type(self.requires_core) is not tuple or len(self.requires_core) != 2
                or any(type(x) is not int for x in self.requires_core)
                or not 0 <= self.requires_core[0] <= CORE_API_MINOR <= self.requires_core[1]):
            raise PluginError()
        for values in (self.formats, self.part_kinds):
            if type(values) is not tuple or len(values) > 1000 or any(type(x) is not str or not _TOKEN.fullmatch(x) for x in values) or len(set(values)) != len(values):
                raise PluginError()
        if self.kind == 'detector' and not self.rules or self.kind == 'extractor' and (self.rules or not self.formats or not self.part_kinds):
            raise PluginError()


class DetectorV2(Protocol):
    def detect(self, text: str, context: DetectionContext): ...


class ExtractorV2(Protocol):
    def extract(self, data: bytes, context: ExtractionContext) -> Extraction: ...


@dataclass(frozen=True)
class LoadedPlugin:
    module: str
    options: dict = field(repr=False)
    api_version: int = 1
    manifest: PluginManifest | None = None
    has_extract: bool = False
    session: object = field(default=None, repr=False, compare=False)


class _PluginSession:
    def __init__(self):
        import threading
        self.lock = threading.RLock()
        self.worker = None
        self.signature = None
        self.starts = 0
        self.requests = 0
        self.closed = False

    def request(self, data, *, timeout, maximum, memory, policy, cancel):
        from ._session import FramedWorker
        with self.lock:
            if self.closed:
                raise WorkerError('worker-start-failed')
            signature = (memory, policy)
            if (self.worker is None or self.worker._closed.is_set() or self.signature != signature
                    or self.worker.process.poll() is not None or self.requests and self.requests % 1000 == 0):
                if self.worker is not None:
                    self.worker.close()
                self.worker = FramedWorker(core_command('leakguard_core.plugin_worker', '--session',
                    search_paths=extension_paths()), memory_bytes=memory, worker_policy=policy)
                self.signature = signature
                self.starts += 1
            worker = self.worker
        try:
            result = worker.request(data, timeout=timeout, maximum=maximum, cancel=cancel)
            with self.lock:
                self.requests += 1
            return result
        except BaseException:
            with self.lock:
                if self.worker is worker and worker._closed.is_set():
                    self.worker = None
            raise

    def close(self):
        # Interrupt an active request without waiting for its serialization lock.
        self.closed = True
        with self.lock:
            worker = self.worker
        if worker is not None:
            try:
                worker.request(b'{"operation":"close"}', timeout=2, maximum=512)
                worker.process.wait(timeout=.25)
            except Exception:
                pass
            worker.close()


def close(instances):
    for instance in instances:
        session = getattr(instance, 'session', None)
        if session is not None:
            session.close()


def session_metrics(instances):
    return tuple({'component': instance.manifest.id, 'starts': instance.session.starts,
                  'requests': instance.session.requests, 'lifetime': 'session'}
                 for instance in instances if isinstance(instance, LoadedPlugin)
                 and instance.session is not None)


def preflight(specifications, *, worker_policy='strict', memory_bytes=512 * 1024 * 1024):
    """Explicit no-input capability probes through the owned worker boundary."""
    from .models import ScanLimits
    instances = []
    statuses = []
    try:
        instances = load(specifications, worker_policy=worker_policy)
        limits = ScanLimits(60, 1, worker_memory_bytes=memory_bytes)
        for instance in instances:
            component = instance.manifest.id if instance.manifest is not None else 'legacy-plugin'
            try:
                response = _request({'module': instance.module, 'options': instance.options},
                    'preflight', {}, timeout=60, limits=limits, worker_policy=worker_policy,
                    session=instance.session)
                if type(response.get('ready')) is not bool:
                    raise PluginError()
                statuses.append(dict(response, component=component))
            except PluginError as error:
                statuses.append({'component': component, 'ready': False, 'code': error.code})
        return tuple(statuses)
    finally:
        close(instances)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError()
        value[key] = item
    return value


def _loads(data):
    def invalid_constant(_value):
        raise ValueError()
    return json.loads(data, object_pairs_hook=_unique, parse_constant=invalid_constant)


def validate_options(schema, options):
    if type(options) is not dict or any(key not in {spec.name for spec in schema.fields} for key in options):
        raise PluginError()
    result = {}
    for spec in schema.fields:
        if spec.name not in options:
            if spec.required:
                raise PluginError()
            if spec.default is None:
                continue
            value = spec.default
        else:
            value = options[spec.name]
        valid = ((spec.kind == 'bool' and type(value) is bool)
                 or (spec.kind == 'int' and type(value) is int and (spec.min_value is None or value >= spec.min_value) and (spec.max_value is None or value <= spec.max_value))
                 or (spec.kind in {'string', 'enum'} and type(value) is str and len(value) <= spec.max_length and (spec.kind != 'enum' or value in spec.choices))
                 or (spec.kind == 'list' and type(value) is list and len(value) <= spec.max_length and all(type(x) in {bool, int, str} and (type(x) is not str or len(x) <= 4096) for x in value)))
        if not valid:
            raise PluginError()
        result[spec.name] = value
    return result


def _manifest_wire(manifest):
    return asdict(manifest) if manifest is not None else None


def _manifest_from_wire(value):
    fields = set(PluginManifest.__dataclass_fields__)
    if type(value) is not dict or not fields - {'worker_lifetime', 'result_schema'} <= set(value) <= fields:
        raise PluginError()
    data = dict(value)
    data['rules'] = tuple(RuleSpec(**x) for x in data['rules'])
    data['dependencies'] = tuple(DistributionSpec(**x) for x in data['dependencies'])
    data['formats'] = tuple(data['formats']); data['part_kinds'] = tuple(data['part_kinds'])
    data['requires_core'] = tuple(data['requires_core'])
    schema = data['options_schema']
    if type(schema) is not dict or set(schema) != {'fields'}:
        raise PluginError()
    fields = []
    for spec in schema['fields']:
        spec = dict(spec); spec['choices'] = tuple(spec['choices']); fields.append(OptionSpec(**spec))
    data['options_schema'] = OptionSchema(tuple(fields))
    return PluginManifest(**data)


def _request(spec, operation, payload, *, timeout=None, limits=None, cancel=None, worker_policy='strict', session=None):
    maximum = getattr(limits, 'max_ipc_bytes', 80_000_000)
    request = {'module': spec['module'], 'options': spec.get('options', {}),
               'component': spec.get('component'), 'operation': operation, **payload}
    try:
        data = json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
        # Extension modules are explicitly selected trusted code. Preserve their
        # bounded parent search roots, while pinning the worker's own core and
        # standard-library imports before any caller-controlled directory.
        if session is not None:
            raw = session.request(data,
                timeout=timeout if timeout is not None else getattr(limits, 'detector_timeout_seconds', 45),
                maximum=maximum, memory=getattr(limits, 'worker_memory_bytes', 512 * 1024 * 1024),
                policy=worker_policy, cancel=cancel)
        else:
            process = run_worker(core_command('leakguard_core.plugin_worker', search_paths=extension_paths()), data,
                             timeout=timeout if timeout is not None else getattr(limits, 'detector_timeout_seconds', 45),
                             max_output_bytes=maximum, max_input_bytes=maximum,
                             memory_bytes=getattr(limits, 'worker_memory_bytes', 512 * 1024 * 1024),
                             env=worker_environment(), cancel=cancel, worker_policy=worker_policy)
            if process.returncode:
                raise PluginError('plugin-crashed')
            raw = process.stdout
        response = _loads(raw)
        if type(response) is not dict:
            raise PluginError()
        if set(response) == {'error'}:
            raise PluginError(response['error'])
        return response
    except WorkerError as error:
        raise PluginError({'worker-timeout': 'plugin-timeout', 'worker-output-limit': 'detector-output-limit',
                           'resource-bound-unavailable': 'resource-bound-unavailable', 'worker-memory-limit': 'worker-memory-limit', 'cancelled': 'cancelled'}.get(error.code, 'plugin-crashed')) from None
    except PluginError:
        raise
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, GeneratorExit)):
            raise
        raise PluginError() from None


def load(specifications, *, timeout=10, limits=None, worker_policy='strict'):
    if type(specifications) not in {list, tuple} or len(specifications) > 100:
        raise PluginError()
    loaded = []
    for spec in specifications:
        try:
            if (type(spec) is not dict or not {'module'} <= set(spec) <= {'module', 'options', 'component'}
                    or type(spec['module']) is not str or not _MODULE.fullmatch(spec['module'])
                    or type(spec.get('options', {})) is not dict):
                raise PluginError()
            response = _request(spec, 'inspect', {}, timeout=timeout, limits=limits, worker_policy=worker_policy)
            if set(response) != {'api_version', 'manifest', 'has_extract'} or type(response['api_version']) is not int or response['api_version'] not in {1, 2} or type(response['has_extract']) is not bool:
                raise PluginError()
            manifest = _manifest_from_wire(response['manifest']) if response['manifest'] is not None else None
            if response['api_version'] == 2 and manifest is None:
                raise PluginError()
            loaded.append(LoadedPlugin(spec['module'], dict(spec.get('options', {})), response['api_version'], manifest, response['has_extract'], _PluginSession() if manifest is not None and manifest.worker_lifetime == 'session' else None))
        except PluginError:
            raise
        except Exception:
            raise PluginError() from None
    return loaded


def detector_id(instance):
    manifest = getattr(instance, 'manifest', None)
    if manifest is None:
        return 'plugin-legacy'
    import hashlib
    return 'plugin-' + (manifest.id if len(manifest.id) <= 73 else hashlib.sha256(manifest.id.encode()).hexdigest())


def _validated_findings(items, text, manifest=None, maximum=100_000):
    line_count = text.count('\n') + 1
    rules = {rule.id: rule.minimum_severity for rule in manifest.rules} if manifest is not None else None
    count = 0
    for item in items:
        count += 1
        if count > maximum:
            raise PluginError('detector-output-limit')
        if (type(item) not in {Finding, NewFinding} or type(item.rule) is not str or not _TOKEN.fullmatch(item.rule)
                or type(item.line) is not int or not 1 <= item.line <= line_count
                or item.severity not in {'block', 'review'}
                or rules is not None and (item.rule not in rules or rules[item.rule] == 'block' and item.severity != 'block')):
            raise PluginError('detector-output-invalid')
        if type(item) is NewFinding:
            if (manifest is None or manifest.result_schema != 2
                    or type(item.analysis) is not AnalysisMetadata
                    or item.analysis.end > len(text)
                    or item.line != text.count('\n', 0, item.analysis.start) + 1):
                raise PluginError('detector-output-invalid')
        yield item


def detect(instances, text, path, part, *, format_id='text', timeout=None, limits=None, cancel=None, worker_policy='strict'):
    maximum = getattr(limits, 'max_findings', 100_000)
    for instance in instances:
        if getattr(instance, 'manifest', None) is not None and instance.manifest.kind != 'detector':
            continue
        manifest = getattr(instance, 'manifest', None)
        if manifest is not None and manifest.result_schema == 2:
            kind = part.rsplit('-', 1)[0] if part.rsplit('-', 1)[-1].isdigit() else part
            if (manifest.formats and format_id not in manifest.formats
                    or manifest.part_kinds and kind not in manifest.part_kinds):
                continue
        try:
            if isinstance(instance, LoadedPlugin):
                response = _request({'module': instance.module, 'options': instance.options}, 'detect',
                                    {'text': text, 'path': str(path), 'part': part, 'format_id': format_id,
                                     'max_findings': maximum}, timeout=timeout, limits=limits, cancel=cancel, worker_policy=worker_policy, session=instance.session)
                if set(response) != {'findings'} or type(response['findings']) is not list:
                    raise PluginError('detector-output-invalid')
                if len(response['findings']) > maximum:
                    raise PluginError('detector-output-limit')
                items = []
                for value in response['findings']:
                    if type(value) is not dict or set(value) not in ({'rule', 'line', 'severity'}, {'rule', 'line', 'severity', 'analysis'}):
                        raise PluginError('detector-output-invalid')
                    if 'analysis' in value:
                        data = dict(value)
                        data['analysis'] = AnalysisMetadata(**data['analysis'])
                        items.append(NewFinding(**data))
                    else:
                        items.append(Finding(**value))
            else:
                # In-memory instances exist only for the deprecated internal API;
                # persistent configured deployment always uses LoadedPlugin.
                if getattr(instance, 'manifest', None) is not None:
                    from .script_checks import ScriptDetector
                    extra = {'worker_policy': worker_policy} if isinstance(instance, ScriptDetector) else {}
                    items = instance.detect(text, DetectionContext(str(path), part, format_id),
                                            timeout=timeout if timeout is not None else 45, limits=limits, cancel=cancel, **extra)
                else:
                    items = instance.detect(text, path, part)
            yield from _validated_findings(items, text, getattr(instance, 'manifest', None), maximum)
        except PluginError:
            raise
        except Exception:
            raise PluginError() from None


def _validate_extraction(result, manifest, bounds):
    if type(result) is not Extraction or result.disposition not in {'extracted', 'unsupported', 'encrypted', 'no-text'} or isinstance(result.parts, (str, bytes, dict)):
        raise PluginError()
    if type(result.issues) not in {tuple, list} or any(code not in _EXTRACT_ISSUES for code in result.issues):
        raise PluginError()
    total = 0; seen = set(); parts = []
    for item in result.parts:
        if len(parts) >= bounds.max_parts:
            raise PluginError('extract-part-limit')
        if (type(item) is not ExtractedPart or item.kind not in manifest.part_kinds
                or type(item.ordinal) is not int or item.ordinal < 1 or type(item.text) is not str
                or (item.kind, item.ordinal) in seen):
            raise PluginError()
        seen.add((item.kind, item.ordinal)); total += len(item.text.encode('utf-8'))
        if total > bounds.max_text_bytes:
            raise PluginError('extract-output-limit')
        parts.append((f'{item.kind}-{item.ordinal}', item.text))
    if result.disposition == 'extracted' and not parts or result.disposition != 'extracted' and parts:
        raise PluginError()
    return parts


def extract(instances, data, path, *, format_id=None, overrides=None, timeout=None, limits=None, cancel=None, worker_policy='strict'):
    bounds = ExtractionLimits.from_scan_limits(limits)
    for instance in instances:
        manifest = getattr(instance, 'manifest', None)
        if manifest is not None and manifest.kind != 'extractor':
            continue
        if manifest is not None:
            explicit = (overrides or {}).get(Path(path).suffix.lower())
            if explicit != manifest.id and (format_id is None or format_id not in manifest.formats):
                continue
        if isinstance(instance, LoadedPlugin):
            if not instance.has_extract:
                continue
            result = extract_component(instance, data, path, format_id=format_id, timeout=timeout, limits=limits, cancel=cancel, worker_policy=worker_policy)
            if result.disposition == 'unsupported':
                continue
            if result.issues or result.disposition != 'extracted':
                raise PluginError(result.issues[0] if result.issues else result.disposition)
            return [(part.part_id, part.text) for part in result.parts]
        method = getattr(instance, 'extract', None)
        if method is None:
            continue
        try:
            result = method(data, path)
            if result is None:
                continue
            parts = []; total = 0
            for name, text in result:
                if type(name) is not str or type(text) is not str or len(name) > 200:
                    raise PluginError()
                total += len(text.encode('utf-8'))
                if total > bounds.max_text_bytes or len(parts) >= bounds.max_parts:
                    raise PluginError('extract-output-limit')
                parts.append((name, text))
            return parts
        except Exception:
            raise PluginError() from None
    return None


def load_scripts(specifications):
    from .script_checks import ScriptDetector
    return [ScriptDetector.from_mapping(spec) for spec in specifications]


def extract_component(instance, data, path, *, format_id=None, timeout=None, limits=None, cancel=None, worker_policy='strict'):
    """Run one explicitly selected extractor, preserving disposition and issues."""
    from .extraction import ExtractionResult, TextPart
    if not isinstance(instance, LoadedPlugin) or not instance.has_extract:
        raise PluginError()
    manifest = instance.manifest
    if manifest is not None and manifest.kind != 'extractor':
        raise PluginError()
    bounds = ExtractionLimits.from_scan_limits(limits)
    if type(data) is not bytes or len(data) > bounds.max_file_bytes:
        raise PluginError('extract-output-limit')
    selected_format = format_id or (manifest.formats[0] if manifest else 'extension')
    if manifest is not None and selected_format not in manifest.formats:
        raise PluginError()
    import base64
    response = _request({'module': instance.module, 'options': instance.options}, 'extract',
                        {'data': base64.b64encode(data).decode('ascii'), 'path': str(path),
                         'format_id': format_id or (manifest.formats[0] if manifest else 'extension'),
                         'limits': asdict(bounds)}, timeout=timeout, limits=limits, cancel=cancel, worker_policy=worker_policy, session=instance.session)
    if set(response) != {'parts', 'disposition', 'issues'}:
        raise PluginError()
    disposition = response['disposition']
    if disposition not in {'extracted', 'unsupported', 'encrypted', 'no-text'}:
        raise PluginError()
    if type(response['issues']) is not list or any(type(code) is not str or code not in _EXTRACT_ISSUES for code in response['issues']):
        raise PluginError()
    if type(response['parts']) is not list:
        raise PluginError()
    if len(response['parts']) > bounds.max_parts:
        raise PluginError('extract-part-limit')
    parts = []; total = 0; seen = set()
    for ordinal, item in enumerate(response['parts'], 1):
        if (type(item) is not list or len(item) != 2 or any(type(x) is not str for x in item)
                or not re.fullmatch(r'[a-z][a-z0-9-]{0,79}-[1-9][0-9]*', item[0]) or item[0] in seen):
            raise PluginError()
        name = item[0]
        kind = name.rsplit('-', 1)[0]
        if manifest is not None and kind not in manifest.part_kinds:
            raise PluginError()
        if manifest is None and name != f'extension-{ordinal}':
            raise PluginError()
        seen.add(name); total += len(item[1].encode('utf-8'))
        if ordinal > bounds.max_parts:
            raise PluginError('extract-part-limit')
        if total > bounds.max_text_bytes:
            raise PluginError('extract-output-limit')
        parts.append(TextPart(name, item[1], selected_format))
    if disposition == 'extracted' and not parts or disposition != 'extracted' and parts:
        raise PluginError()
    issues = tuple(response['issues'])
    if disposition != 'extracted' and not issues:
        issues = ({'unsupported': 'unsupported-format', 'encrypted': 'encrypted', 'no-text': 'no-text'}[disposition],)
    return ExtractionResult(selected_format, disposition, tuple(parts), issues)
