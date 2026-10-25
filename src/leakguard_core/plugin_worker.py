"""Private trusted extension worker. Protocol errors never expose input or traces."""
import base64
from dataclasses import asdict
import importlib
import json
import sys

from . import plugins as p
from .extraction import ExtractionContext, ExtractionLimits


def execute(request):
    module_name = request['module']
    if type(module_name) is not str or not p._MODULE.fullmatch(module_name):
        raise p.PluginError()
    module = importlib.import_module(module_name)
    version = getattr(module, 'API_VERSION', None)
    if type(version) is not int or version not in {1, 2}:
        raise p.PluginError()
    manifest = None
    options = request['options']
    if version == 2:
        manifest = getattr(module, 'MANIFEST', None)
        if type(manifest) is not p.PluginManifest:
            raise p.PluginError()
        # Reconstruct to reject mutated/faked dataclass values from trusted code.
        manifest = p._manifest_from_wire(json.loads(json.dumps(p._manifest_wire(manifest))))
        if request.get('component') is not None and request['component'] != manifest.id:
            raise p.PluginError()
        options = p.validate_options(manifest.options_schema, options)
    elif request.get('component') is not None:
        raise p.PluginError()
    if type(options) is not dict:
        raise p.PluginError()
    instance = module.create_plugin(dict(options))
    if manifest is None and not callable(getattr(instance, 'detect', None)):
        raise p.PluginError()
    if manifest is not None and not callable(getattr(instance, manifest.kind == 'detector' and 'detect' or 'extract', None)):
        raise p.PluginError()
    operation = request['operation']
    if operation == 'inspect':
        return {'api_version': version, 'manifest': p._manifest_wire(manifest),
                'has_extract': callable(getattr(instance, 'extract', None))}
    if operation == 'detect':
        if manifest is not None and manifest.kind != 'detector':
            raise p.PluginError()
        text, path, part, format_id = (request[key] for key in ('text', 'path', 'part', 'format_id'))
        if any(type(x) is not str for x in (text, path, part, format_id)):
            raise p.PluginError()
        items = instance.detect(text, p.DetectionContext(path, part, format_id)) if version == 2 else instance.detect(text, path, part)
        findings = list(p._validated_findings(items, text, manifest, request['max_findings']))
        return {'findings': [asdict(item) for item in findings]}
    if operation == 'extract':
        bounds = ExtractionLimits(**request['limits'])
        data = base64.b64decode(request['data'], validate=True)
        if len(data) > bounds.max_file_bytes:
            raise p.PluginError('extract-output-limit')
        if version == 2:
            result = instance.extract(data, ExtractionContext(request['path'], request['format_id'], bounds))
            parts = p._validate_extraction(result, manifest, bounds)
            return {'disposition': result.disposition, 'parts': parts, 'issues': list(result.issues)}
        method = getattr(instance, 'extract', None)
        result = method(data, request['path']) if method else None
        if result is None:
            return {'disposition': 'unsupported', 'parts': [], 'issues': []}
        total = 0; parts = []
        for name, text in result:
            if type(name) is not str or type(text) is not str or len(name) > 200:
                raise p.PluginError()
            total += len(text.encode('utf-8'))
            if total > bounds.max_text_bytes:
                raise p.PluginError('extract-output-limit')
            if len(parts) >= bounds.max_parts:
                raise p.PluginError('extract-part-limit')
            parts.append((f'extension-{len(parts) + 1}', text))
        return {'disposition': 'extracted' if parts else 'no-text', 'parts': parts,
                'issues': [] if parts else ['no-text']}
    raise p.PluginError()


def main():
    try:
        raw = sys.stdin.buffer.read(80_000_001)
        if len(raw) > 80_000_000:
            raise p.PluginError('detector-output-limit')
        request = p._loads(raw)
        response = execute(request)
        output = json.dumps(response, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if len(output) > 80_000_000:
            raise p.PluginError('detector-output-limit')
        sys.stdout.buffer.write(output)
    except ModuleNotFoundError:
        sys.stdout.buffer.write(b'{"error":"dependency-unavailable"}')
    except p.PluginError as error:
        sys.stdout.buffer.write(json.dumps({'error': error.code}).encode())
    except BaseException:
        sys.stdout.buffer.write(b'{"error":"plugin-invalid"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
