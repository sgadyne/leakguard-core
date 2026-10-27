"""Bounded flat-field scanner. It does not evaluate or dereference expressions."""
from __future__ import annotations

import re
from .aliases import AliasPack, normalize_key
from .types import CredentialSpan

RULES = {
    'password': 'credential-password',
    'api-key': 'credential-api-key',
    'client-secret': 'credential-client-secret',
    'access-token': 'credential-access-token',
    'private-key': 'credential-private-key',
}
MAX_TEXT = 10_000_000
MAX_VALUE = 4096
MAX_FIELDS = 100_000
MAX_SPANS = 10_000
_KEY = r'[A-Za-z][A-Za-z0-9_.-]{0,127}'
_FIELD = re.compile(r'(?<![\w.\-])(?:"(?P<double>' + _KEY + r')"|\'(?P<single>' + _KEY + r')\'|(?P<bare>' + _KEY + r'))[ \t]*[:=][ \t]*')
_REFERENCE = re.compile(
    r'(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}'
    r'|os\.getenv\([ \t]*["\'][A-Za-z_][A-Za-z0-9_]*["\'][ \t]*\)'
    r'|os\.environ\[[ \t]*["\'][A-Za-z_][A-Za-z0-9_]*["\'][ \t]*\]'
    r'|getenv\([ \t]*["\'][A-Za-z_][A-Za-z0-9_]*["\'][ \t]*\))\Z', re.ASCII)

_PLACEHOLDER_PATTERN = r'(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\}|<[A-Za-z_][A-Za-z0-9_]*>)'
_PLACEHOLDER = re.compile(_PLACEHOLDER_PATTERN + r'\Z', re.ASCII)
_PLACEHOLDER_PREFIX = re.compile(_PLACEHOLDER_PATTERN, re.ASCII)


def scan_fields(text: str, pack: AliasPack) -> tuple[CredentialSpan, ...]:
    """Scan flat assignments, returning offsets over literal value content only.

    Quoted values are literals except pure documented placeholder forms;
    unquoted supported environment expressions and nulls are not literals.
    Malformed quotes are ignored. Bounds fail closed with a value-free error.
    """
    if type(text) is not str or type(pack) is not AliasPack:
        raise ValueError('invalid scan input')
    if len(text) > MAX_TEXT:
        raise ValueError('field input limit exceeded')
    result: list[CredentialSpan] = []
    cursor = 0
    fields = 0
    while match := _FIELD.search(text, cursor):
        fields += 1
        if fields > MAX_FIELDS:
            raise ValueError('field count limit exceeded')
        key = match.group('double') or match.group('single') or match.group('bare')
        role = pack.aliases.get(normalize_key(key))
        start = match.end()
        cursor = start
        if role is None or start >= len(text):
            continue
        quoted = text[start] in "\"'"
        if quoted:
            quote = text[start]
            start += 1
            end = start
            escaped = False
            while end < len(text) and text[end] not in '\r\n' and end - start <= MAX_VALUE:
                ch = text[end]
                if ch == quote and not escaped:
                    break
                if ch == '\\' and not escaped:
                    escaped = True
                else:
                    escaped = False
                end += 1
            if end - start > MAX_VALUE:
                raise ValueError('field value limit exceeded')
            if end >= len(text) or text[end] != quote:
                cursor = end
                continue
            cursor = end + 1
            if _PLACEHOLDER.fullmatch(text[start:end]):
                continue
        else:
            prefix = _PLACEHOLDER_PREFIX.match(text, start)
            end = prefix.end() if prefix else start
            while end < len(text) and text[end] not in ',;}\r\n' and end - start <= MAX_VALUE:
                end += 1
            if end - start > MAX_VALUE:
                raise ValueError('field value limit exceeded')
            cursor = end
            # Trailing whitespace is not part of the literal location.
            while end > start and text[end - 1] in ' \t':
                end -= 1
            raw = text[start:end]
            if raw.lower() in {'null', 'none', '~', 'true', 'false'} or _REFERENCE.fullmatch(raw) or _PLACEHOLDER.fullmatch(raw):
                continue
        if end > start:
            if len(result) >= MAX_SPANS:
                raise ValueError('field finding limit exceeded')
            result.append(CredentialSpan(RULES[role], start, end))
    return tuple(result)
