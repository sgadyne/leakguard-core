"""Small typed artifact checks, independent of credential aliases and syntax.

Only validated structural contexts authorize label masking. Unknown schemas,
malformed data, size limits and ambiguous locations grant no exemption.
"""
from __future__ import annotations

import base64
from bisect import bisect_left, bisect_right
import binascii
from dataclasses import dataclass, field
import json
import re
import xml.etree.ElementTree as ET

MAX_TEXT = 12_000_000
MAX_DATA = 262_144
MAX_DECODED_TOTAL = 1_048_576
# Identical to the explicitly pinned bundled AWS rule (Gitleaks8.30.1).
# All lexical candidates on a source line must have the approved schema role;
# otherwise line-only native provenance grants no severity reduction.
AWS_ACCESS_PATTERN = r'\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'
_AWS_ACCESS = re.compile(AWS_ACCESS_PATTERN, re.ASCII)

@dataclass(frozen=True, slots=True)
class ArtifactContext:
    masks: tuple[tuple[int, int], ...] = ()
    binary_lines: tuple[tuple[int, int], ...] = ()
    # Raw XML scalar offsets preserve source coordinates; values stay private.
    plist_fields: tuple[tuple[str, int, int], ...] = field(default=(), repr=False)
    aws_review_lines: frozenset[int] = frozenset()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json_scalars(text):
    """Bounded scalar projection over strict JSON, preserving raw offsets."""
    doc = json.loads(text, object_pairs_hook=_unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    decoder = json.JSONDecoder()
    count = 0
    def space(pos):
        while pos < len(text) and text[pos] in ' \t\r\n':pos += 1
        return pos
    def walk(pos, path, depth):
        nonlocal count
        if depth > 64:raise ValueError()
        pos = space(pos)
        if text[pos] == '{':
            pos = space(pos + 1)
            while text[pos] != '}':
                key, pos = decoder.raw_decode(text, pos)
                pos = space(pos)
                pos, leaves = walk(pos + 1, path + (key,), depth + 1)
                for leaf in leaves:
                    yield_leaf.append(leaf)
                # Children append directly to the shared bounded list.
                pos = space(pos)
                if text[pos] == ',':pos = space(pos + 1)
            return pos + 1, ()
        if text[pos] == '[':
            pos = space(pos + 1); index = 0
            while text[pos] != ']':
                pos, leaves = walk(pos, path + (index,), depth + 1)
                for leaf in leaves:yield_leaf.append(leaf)
                index += 1;pos = space(pos)
                if text[pos] == ',':pos = space(pos + 1)
            return pos + 1, ()
        value, end = decoder.raw_decode(text, pos)
        count += 1
        if count > 100_000:raise ValueError()
        return end, ((path, pos, end, value),)
    yield_leaf = []
    end, leaves = walk(0, (), 0)
    yield_leaf.extend(leaves)
    return doc, yield_leaf


def _der_tlv(data, pos):
    if pos + 2 > len(data):raise ValueError()
    tag = data[pos]; length = data[pos + 1];pos += 2
    if length & 128:
        width = length & 127
        if not 1 <= width <= 2 or pos + width > len(data) or data[pos] == 0:raise ValueError()
        length = int.from_bytes(data[pos:pos + width], 'big');pos += width
        if length < 128:raise ValueError()
    end = pos + length
    if end > len(data):raise ValueError()
    return tag, pos, end


def is_rsa_public_spki(value):
    """Validate a bounded DER RSA SubjectPublicKeyInfo, never private key data.

    No key is evaluated, authenticated or used. Other public-key encodings stay
    candidates until an explicit validator is added.
    """
    if type(value) is not str or not 128 <= len(value) <= 8192:return False
    try:
        data = base64.b64decode(value, validate=True)
        if base64.b64encode(data).decode('ascii') != value:return False
        tag, start, end = _der_tlv(data, 0)
        if tag != 0x30 or end != len(data):return False
        tag, alg, alg_end = _der_tlv(data, start)
        if tag != 0x30 or data[alg:alg_end] != bytes.fromhex('06092a864886f70d0101010500'):return False
        tag, bits, bits_end = _der_tlv(data, alg_end)
        if tag != 3 or bits_end != end or data[bits] != 0:return False
        tag, key, key_end = _der_tlv(data, bits + 1)
        if tag != 0x30 or key_end != bits_end:return False
        tag, modulus, modulus_end = _der_tlv(data, key)
        if tag != 2 or not 128 <= modulus_end - modulus <= 1025:return False
        integer = data[modulus:modulus_end]
        if not integer or integer[0] & 128 or integer[0] == 0 and (len(integer) < 2 or not integer[1] & 128):return False
        tag, exponent, exponent_end = _der_tlv(data, modulus_end)
        if tag != 2 or exponent_end != key_end or not 1 <= exponent_end - exponent <= 8:return False
        exponent_value = int.from_bytes(data[exponent:exponent_end], 'big')
        return exponent_value >= 3 and exponent_value % 2 == 1
    except (ValueError, binascii.Error, IndexError, UnicodeError):
        return False


def _plist(text):
    if '<!ENTITY' in text.upper() or re.search(r'<!DOCTYPE[^>]*\[', text, re.I):return False
    try:
        doc = ET.fromstring(text)
        return doc.tag == 'plist' and doc.attrib.get('version') == '1.0' and len(doc) == 1
    except (ET.ParseError, ValueError, RecursionError):return False


def inspect_artifact(text):
    if len(text) > MAX_TEXT:return ArtifactContext()
    masks = [];binary_lines = [];fields = [];aws_review_lines = set()
    newline_positions = None
    def line_at(position):
        nonlocal newline_positions
        if newline_positions is None:
            newline_positions = [index for index, char in enumerate(text) if char == '\n']
        return bisect_left(newline_positions, position) + 1
    stripped = text.lstrip()
    if stripped.startswith(('{', '[')) and ('"localizationKey"' in text or '"manifest_version"' in text or stripped.startswith('[') and '"regex"' in text):
        try:
            doc, scalars = _json_scalars(text)
            manifest = (type(doc) is dict and type(doc.get('manifest_version')) is int
                        and doc['manifest_version'] in {2, 3}
                        and type(doc.get('name')) is str and type(doc.get('version')) is str)
            signature_schema = (type(doc) is list and 0 < len(doc) <= 50_000 and all(
                type(item) is dict and set(item) == {'hash', 'regex'} and
                type(item['regex']) is str and len(item['regex']) <= 4096 and
                (type(item['hash']) is int and 0 <= item['hash'] < 2**64 or
                 type(item['hash']) is str and re.fullmatch(r'[A-Fa-f0-9]{8,128}', item['hash']))
                for item in doc))
            signature_ranges = []
            for path, start, end, value in scalars:
                if (signature_schema and len(path) == 2 and path[-1] == 'regex' and
                        type(value) is str and 1000 <= len(value) <= 4096 and
                        value.startswith('(?i)^') and '(' in value[5:] and '\\' in value):
                    signature_ranges.append((start, end))
                if path and path[-1] == 'localizationKey':
                    # Exact metadata role, not a generic exemption for "key".
                    prefix = text[max(0, start - 200):start]
                    match = re.search(r'"localizationKey"[ \t\r\n]*:[ \t\r\n]*$', prefix)
                    if match:
                        key_start = max(0, start - 200) + match.start() + 1
                        masks.append((key_start, key_start + len('localizationKey')))
                if (manifest and path == ('key',) and type(value) is str
                        and text[start + 1:end - 1] == value and is_rsa_public_spki(value)):
                    masks.append((start + 1, end - 1))
            if signature_ranges:
                signature_ranges.sort()
                starts = [start for start, _ in signature_ranges]
                eligible = set();untrusted = set()
                for match in _AWS_ACCESS.finditer(text):
                    start, end = match.span(1);line = line_at(start)
                    index = bisect_right(starts, start) - 1
                    if index >= 0 and end <= signature_ranges[index][1]:
                        eligible.add(line)
                    else:
                        untrusted.add(line)
                # A real/unknown AWS-shaped sibling on the same minified line
                # prevents downgrading *any* native observation on that line.
                aws_review_lines = eligible - untrusted
        except (ValueError, TypeError, IndexError, RecursionError):pass
    if '<plist' in text[:2048] and _plist(text):
        # XML <key> is a dictionary tag. Leave its contents and every other
        # scalar visible to provider token and private-key recognizers.
        masks.extend((m.start() + 1, m.start() + 4) for m in re.finditer(r'<key>', text))
        pattern = re.compile(r'<key>(?P<key>[^<&]{1,128})</key>[ \t\r\n]*<(?P<kind>string|data)>(?P<value>[^<]*)</(?P=kind)>')
        for match in pattern.finditer(text):
            start, end = match.span('value')
            if end - start <= MAX_DATA * 2 and match.group('value').strip():
                fields.append((match.group('key'), start, end))
        decoded_total = 0
        for match in re.finditer(r'<data>(?P<value>[^<]*)</data>', text):
            start, end = match.span('value');raw = match.group('value')
            if len(raw) > MAX_DATA * 2:continue
            compact = re.sub(r'[ \t\r\n]', '', raw)
            if len(compact) > MAX_DATA * 4 // 3 + 4:continue
            try:decoded = base64.b64decode(compact, validate=True)
            except (ValueError, binascii.Error):continue
            decoded_total += len(decoded)
            if decoded_total > MAX_DECODED_TOTAL:break
            if not decoded.startswith((b'bplist00', b'\x89PNG\r\n\x1a\n', b'GIF87a', b'GIF89a', b'\xff\xd8\xff', b'PK\x03\x04')):continue
            # Only wholly contained source lines can receive a lower severity.
            # A minified/mixed line cannot identify which native object matched.
            # The opening/closing tag lines cannot be wholly data. A lazy
            # newline index avoids quadratic prefix scans on large plists.
            first = line_at(start) + 1
            last = line_at(end) - 1
            if first <= last:binary_lines.append((first, last))
    return ArtifactContext(tuple(masks), tuple(binary_lines), tuple(fields), frozenset(aws_review_lines))


def mask_artifact_labels(text, context):
    pieces = [];cursor = 0
    for start, end in sorted(context.masks):
        if start < cursor:continue
        pieces.extend((text[cursor:start], ' ' * (end - start)));cursor = end
    pieces.append(text[cursor:])
    return ''.join(pieces)


def native_severity(rule, first, last, context):
    if rule == 'aws-access-token' and first == last and first in context.aws_review_lines:
        return 'review'
    if rule in {'square-access-token', 'generic-api-key'} and any(
            start <= first <= last <= end for start, end in context.binary_lines):
        return 'review'
    return 'block'
