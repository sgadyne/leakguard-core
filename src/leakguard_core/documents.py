"""Maintained text/document adapters. They never execute document code/macros.

The core calls document adapters inside a supervised resource-bounded worker.
The compatibility generator below is retained for 0.1 callers.
"""
from __future__ import annotations

import io
from pathlib import PurePath
import zipfile
import xml.etree.ElementTree as ET

from .extraction import DOCUMENT_FORMATS, ExtractionLimits, ExtractionResult, TextPart

DOCUMENT_SUFFIXES = set(DOCUMENT_FORMATS)


class ExtractionFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def extract_document(data: bytes, format_id: str, limits: ExtractionLimits) -> ExtractionResult:
    parts = []; issues = []; total = 0

    def add(kind, ordinal, text):
        nonlocal total
        if len(parts) >= limits.max_parts:
            raise ExtractionFailure('extract-part-limit')
        total += len(text.encode('utf-8'))
        if total > limits.max_text_bytes:
            raise ExtractionFailure('extract-output-limit')
        parts.append(TextPart(f'{kind}-{ordinal}', text, format_id))

    try:
        if format_id.startswith('office-'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members) > limits.max_archive_members:
                    raise ExtractionFailure('extract-part-limit')
                names = [member.filename for member in members]
                if len(set(names)) != len(names):
                    raise ExtractionFailure('extract-failed')
                families = []
                if 'word/document.xml' in names:
                    families.append('office-word')
                if any(name.startswith('xl/worksheets/') and name.endswith('.xml') for name in names):
                    families.append('office-sheet')
                if any(name.startswith('ppt/slides/slide') and name.endswith('.xml') for name in names):
                    families.append('office-slides')
                if len(families) > 1:
                    raise ExtractionFailure('ambiguous-format')
                if not families:
                    if format_id == 'office-auto':
                        return ExtractionResult('binary', 'unsupported', issues=('unsupported-format',))
                    raise ExtractionFailure('extract-failed')
                if format_id != 'office-auto' and families[0] != format_id:
                    raise ExtractionFailure('format-mismatch')
                format_id = families[0]
                read_bytes = 0; ordinal = 0; property_ordinal = 0
                for member in members:
                    name = member.filename
                    if not name.endswith('.xml') or not name.startswith(('word/', 'xl/sharedStrings', 'xl/worksheets/', 'ppt/slides/', 'docProps/')):
                        continue
                    if member.flag_bits & 1:
                        raise ExtractionFailure('encrypted')
                    if member.file_size > limits.max_member_bytes:
                        raise ExtractionFailure('extract-output-limit')
                    read_bytes += member.file_size
                    if read_bytes > limits.max_text_bytes:
                        raise ExtractionFailure('extract-output-limit')
                    with archive.open(member) as stream:
                        xml = stream.read(limits.max_member_bytes + 1)
                    if len(xml) > limits.max_member_bytes:
                        raise ExtractionFailure('extract-output-limit')
                    # Reject entities/DTDs before XML parsing, including UTF-16 XML.
                    safe_xml = xml.replace(b'\x00', b'').upper()
                    if b'<!DOCTYPE' in safe_xml or b'<!ENTITY' in safe_xml:
                        raise ExtractionFailure('extract-failed')
                    root = ET.fromstring(xml)
                    text = '\n'.join(value for value in root.itertext() if value.strip())
                    if not text:
                        continue
                    if name.startswith('docProps/'):
                        property_ordinal += 1; add('office-properties', property_ordinal, text)
                    else:
                        ordinal += 1; add(format_id, ordinal, text)
                if not parts:
                    issues.append('no-text')
        elif format_id == 'pdf-text':
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data), strict=True)
            if reader.is_encrypted:
                raise ExtractionFailure('encrypted')
            if len(reader.pages) > limits.max_pages:
                raise ExtractionFailure('extract-part-limit')
            if not reader.pages:
                issues.append('no-text')
            for ordinal, page in enumerate(reader.pages, 1):
                text = page.extract_text() or ''
                if not text.strip():
                    issues.append('no-text')
                else:
                    add('pdf-page', ordinal, text)
        elif format_id in {'outlook-msg', 'ole-auto'}:
            import olefile
            with olefile.OleFileIO(io.BytesIO(data)) as message:
                entries = message.listdir()
                if len(entries) > limits.max_archive_members:
                    raise ExtractionFailure('extract-part-limit')
                selected = [entry for entry in entries if entry and entry[-1].startswith('__substg1.0_')
                            and entry[-1][12:16] in {'1000', '0037', '007D'}
                            and not any(p.startswith(('__attach_', '__recip_')) for p in entry[:-1])]
                if format_id == 'ole-auto' and not selected:
                    return ExtractionResult('binary', 'unsupported', issues=('unsupported-format',))
                format_id = 'outlook-msg'
                counts = {'1000': 0, '0037': 0, '007D': 0}
                kinds = {'1000': 'msg-body', '0037': 'msg-subject', '007D': 'msg-header'}
                for entry in selected:
                    name = entry[-1]
                    if not name.endswith(('001F', '001E')):
                        issues.append('decode-failed'); continue
                    if message.get_size(entry) > limits.max_member_bytes:
                        raise ExtractionFailure('extract-output-limit')
                    raw = message.openstream(entry).read(limits.max_member_bytes + 1)
                    if len(raw) > limits.max_member_bytes:
                        raise ExtractionFailure('extract-output-limit')
                    # ANSI stream code pages need a declared mapping. cp1252 is
                    # the maintained fallback surface; undefined bytes fail.
                    text = raw.decode('utf-16-le' if name.endswith('001F') else 'cp1252', errors='strict').rstrip('\x00')
                    field = name[12:16]
                    if text.strip():
                        counts[field] += 1; add(kinds[field], counts[field], text)
                if not parts:
                    issues.append('no-text')
        else:
            return ExtractionResult('binary', 'unsupported', issues=('unsupported-format',))
    except ExtractionFailure as error:
        issues.append(error.code)
    except ImportError:
        issues.append('dependency-unavailable')
    except UnicodeError:
        issues.append('decode-failed')
    except Exception:
        issues.append('extract-failed')
    disposition = 'extracted' if not issues and parts else ('encrypted' if 'encrypted' in issues and not parts else 'no-text' if issues == ['no-text'] and not parts else 'error')
    return ExtractionResult(format_id, disposition, tuple(parts), tuple(dict.fromkeys(issues)))


def extract(data, filename):
    """Deprecated 0.1 generator. New code uses extraction.extract and its issues."""
    from .extraction import sniff
    format_id, issue = sniff(data, filename)
    if issue:
        if issue == 'unsupported-format':
            return
        raise ExtractionFailure(issue)
    if format_id == 'text':
        try:
            text = data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig', errors='strict')
        except UnicodeError:
            return
        yield 'text', text
        return
    result = extract_document(data, format_id, ExtractionLimits())
    if result.issues and result.issues != ('no-text',) and result.issues != ('unsupported-format',):
        raise ExtractionFailure(result.issues[0])
    for part in result.parts:
        yield part.part_id, part.text
