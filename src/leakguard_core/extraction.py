"""Core format routing and bounded extraction of independent text parts."""
from __future__ import annotations

from dataclasses import dataclass
import base64
import json
from pathlib import PurePath
import os
import sys

from ._supervision import WorkerError, run_worker, worker_environment

DOCUMENT_FORMATS = {
    '.docx': 'office-word', '.xlsx': 'office-sheet', '.xlsm': 'office-sheet',
    '.pptx': 'office-slides', '.pdf': 'pdf-text', '.msg': 'outlook-msg',
}
DOCUMENT_OMISSIONS = {
    'office-word': 'office-nontext', 'office-sheet': 'office-nontext',
    'office-slides': 'office-nontext', 'pdf-text': 'pdf-images',
    'outlook-msg': 'msg-attachments',
}


@dataclass(frozen=True)
class ExtractionLimits:
    max_file_bytes: int = 20_971_520
    max_parts: int = 1000
    max_text_bytes: int = 12_000_000
    max_member_bytes: int = 5_000_000
    max_archive_members: int = 10_000
    max_pages: int = 300
    max_ipc_bytes: int = 80_000_000
    worker_memory_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError('configuration-invalid')

    @classmethod
    def from_scan_limits(cls, limits=None):
        if limits is None:
            return cls()
        return cls(**{key: getattr(limits, key) for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class TextPart:
    part_id: str
    text: str
    format_id: str


@dataclass(frozen=True)
class ExtractionResult:
    format_id: str
    disposition: str
    parts: tuple[TextPart, ...] = ()
    issues: tuple[str, ...] = ()


_EXTRACT_CODES = frozenset({
    'input-limit', 'unsupported-format', 'format-mismatch', 'ambiguous-format',
    'decode-failed', 'encrypted', 'no-text', 'dependency-unavailable', 'extract-failed',
    'extract-timeout', 'extract-crashed', 'extract-output-limit', 'extract-part-limit',
    'resource-bound-unavailable', 'cancelled',
})


def sniff(data: bytes, logical_path: str) -> tuple[str, str | None]:
    """Return core format and optional failure, never a successful parser claim."""
    hint = DOCUMENT_FORMATS.get(PurePath(logical_path).suffix.lower())
    if data.startswith(b'%PDF-'):
        return ('pdf-text', 'format-mismatch' if hint and hint != 'pdf-text' else None)
    if data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
        if hint and not hint.startswith('office-'):
            return hint, 'format-mismatch'
        return hint or 'office-auto', None
    if data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        if hint and hint != 'outlook-msg':
            return hint, 'format-mismatch'
        return hint or 'ole-auto', None
    if hint:
        return hint, 'format-mismatch'
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return 'text', None
    if b'\x00' in data[:8192]:
        return 'binary', 'unsupported-format'
    return 'text', None


def extract(data: bytes, logical_path: str, *, limits=None, timeout: float | None = None,
            plugins=(), cancel=None) -> ExtractionResult:
    bounds = ExtractionLimits.from_scan_limits(limits)
    if type(data) is not bytes or len(data) > bounds.max_file_bytes:
        return ExtractionResult('unknown', 'error', issues=('input-limit',))
    format_id, issue = sniff(data, logical_path)
    if issue:
        return ExtractionResult(format_id, 'unsupported' if issue == 'unsupported-format' else 'error', issues=(issue,))
    # Explicit legacy extension extractors may select otherwise unsupported input.
    # The registry adapter validates parts and creates static report labels.
    if plugins:
        from . import plugins as registry
        provided = registry.extract(plugins, data, logical_path)
        if provided is not None:
            total = 0; parts = []
            for ordinal, (_, text) in enumerate(provided, 1):
                total += len(text.encode('utf-8'))
                if ordinal > bounds.max_parts:
                    return ExtractionResult('extension', 'error', tuple(parts), ('extract-part-limit',))
                if total > bounds.max_text_bytes:
                    return ExtractionResult('extension', 'error', tuple(parts), ('extract-output-limit',))
                parts.append(TextPart(f'extension-{ordinal}', text, 'extension'))
            return ExtractionResult('extension', 'extracted' if parts else 'no-text', tuple(parts), () if parts else ('no-text',))
    if format_id == 'text':
        try:
            text = data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig', errors='strict')
        except UnicodeError:
            return ExtractionResult('text', 'error', issues=('decode-failed',))
        if len(text.encode('utf-8')) > bounds.max_text_bytes:
            return ExtractionResult('text', 'error', issues=('extract-output-limit',))
        return ExtractionResult('text', 'extracted', (TextPart('text', text, 'text'),))
    request = {'schema_version': 1, 'format_id': format_id,
               'limits': {key: getattr(bounds, key) for key in bounds.__dataclass_fields__},
               'data': base64.b64encode(data).decode('ascii')}
    env = worker_environment({'PYTHONPATH': os.pathsep.join(sys.path)})
    try:
        process = run_worker([sys.executable, '-X', 'utf8', '-m', 'leakguard_core.extract_worker', '--v2'],
                             json.dumps(request, separators=(',', ':')).encode(),
                             timeout=timeout if timeout is not None else getattr(limits, 'extract_timeout_seconds', 25),
                             max_output_bytes=bounds.max_ipc_bytes, max_input_bytes=bounds.max_ipc_bytes,
                             memory_bytes=bounds.worker_memory_bytes, env=env, cancel=cancel)
    except WorkerError as error:
        code = {'worker-timeout': 'extract-timeout', 'worker-output-limit': 'extract-output-limit',
                'resource-bound-unavailable': 'resource-bound-unavailable', 'cancelled': 'cancelled'}.get(error.code, 'extract-crashed')
        return ExtractionResult(format_id, 'error', issues=(code,))
    if process.returncode:
        return ExtractionResult(format_id, 'error', issues=('extract-crashed',))
    try:
        result = json.loads(process.stdout)
        if type(result) is not dict or set(result) != {'format_id', 'disposition', 'parts', 'issues'}:
            raise ValueError
        if result['format_id'] not in {'office-word', 'office-sheet', 'office-slides', 'pdf-text', 'outlook-msg', 'binary'}:
            raise ValueError
        if result['disposition'] not in {'extracted', 'unsupported', 'encrypted', 'no-text', 'error'}:
            raise ValueError
        if type(result['issues']) is not list or any(code not in _EXTRACT_CODES for code in result['issues']):
            raise ValueError
        parts = []; total = 0
        if type(result['parts']) is not list or len(result['parts']) > bounds.max_parts:
            raise ValueError
        import re
        ids = set()
        for item in result['parts']:
            if type(item) is not dict or set(item) != {'part_id', 'text'}:
                raise ValueError
            name, text = item['part_id'], item['text']
            if type(name) is not str or not re.fullmatch(r'(?:office-word|office-sheet|office-slides|office-properties|pdf-page|msg-body|msg-subject|msg-header)-[1-9][0-9]*', name) or name in ids or type(text) is not str:
                raise ValueError
            ids.add(name); total += len(text.encode('utf-8'))
            if total > bounds.max_text_bytes:
                raise ValueError
            parts.append(TextPart(name, text, result['format_id']))
        if result['disposition'] == 'extracted' and not parts:
            raise ValueError
        return ExtractionResult(result['format_id'], result['disposition'], tuple(parts), tuple(result['issues']))
    except (ValueError, TypeError, KeyError, UnicodeError):
        return ExtractionResult(format_id, 'error', issues=('extract-failed',))
