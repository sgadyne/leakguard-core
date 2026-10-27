"""Bounded flat-field scanner. It does not evaluate or dereference expressions."""
from __future__ import annotations

import re
import unicodedata
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
_TOKEN = re.compile(_FIELD.pattern + r'''|(?P<quote>["'])''')
_REFERENCE = re.compile(
    r'(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}'
    r'|os\.getenv\([ \t]*["\'][A-Za-z_][A-Za-z0-9_]*["\'][ \t]*\)'
    r'|os\.environ\[[ \t]*["\'][A-Za-z_][A-Za-z0-9_]*["\'][ \t]*\]'
    r'|getenv\([ \t]*["\'][A-Za-z_][A-Za-z0-9_]*["\'][ \t]*\))\Z', re.ASCII)

_PLACEHOLDER_PATTERN = r'(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\}|<[A-Za-z_][A-Za-z0-9_]*>)'
_PLACEHOLDER = re.compile(_PLACEHOLDER_PATTERN + r'\Z', re.ASCII)
_PLACEHOLDER_PREFIX = re.compile(_PLACEHOLDER_PATTERN, re.ASCII)

# An intentionally narrow lexical exemption, not expression evaluation. The
# whole line must consist of this lookup; concatenation, literal fallbacks,
# comments, other assignments and quoted expression text remain candidates.
_EMPTY_CREDENTIAL_LOOKUP = re.compile(
    r'''[ \t]*password[ \t]*=[ \t]*credentials\.get\([ \t]*(?:"password"|'password')[ \t]*,[ \t]*(?:""|'')[ \t]*\)[ \t]*,?[ \t]*\r?\Z''',
    re.ASCII)


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
    while match := _TOKEN.search(text, cursor):
        # Consume quoted text as a whole, including arbitrary unknown keys.
        # The field alternative wins when the quote starts a valid alias key.
        if match.group('quote'):
            quote = match.group('quote')
            pos = match.end()
            escaped = False
            while pos < len(text) and text[pos] not in '\r\n':
                ch = text[pos]
                if ch == quote and not escaped:
                    pos += 1
                    break
                escaped = ch == '\\' and not escaped
                pos += 1
            cursor = pos
            continue
        # Combining marks are identifier continuations but are not matched by
        # Python's Unicode \w. Never promote the suffix of a larger key.
        if match.start() and unicodedata.category(text[match.start() - 1]).startswith('M'):
            cursor = match.end()
            continue
        fields += 1
        if fields > MAX_FIELDS:
            raise ValueError('field count limit exceeded')
        key = match.group('double') or match.group('single') or match.group('bare')
        role = pack.aliases.get(normalize_key(key))
        start = match.end()
        cursor = start
        if key == 'password' and match.group('bare'):
            line_start = text.rfind('\n', 0, match.start()) + 1
            line_end = text.find('\n', start)
            if line_end < 0:
                line_end = len(text)
            if _EMPTY_CREDENTIAL_LOOKUP.fullmatch(text[line_start:line_end]):
                cursor = line_end
                continue
        if start >= len(text):
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
            tail = cursor
            while tail < len(text) and text[tail] in ' \t':
                tail += 1
            if tail < len(text) and text[tail] not in ',;}] )\r\n#':
                # A closing quote immediately followed by junk is malformed.
                # Consume the rest of this scalar to avoid rescanning it.
                while tail < len(text) and text[tail] not in ',;}\r\n':
                    tail += 1
                cursor = tail
                continue
            if role is None or _PLACEHOLDER.fullmatch(text[start:end]):
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
            if role is None:
                continue
            raw = text[start:end]
            if raw.lower() in {'null', 'none', '~', 'true', 'false'} or _REFERENCE.fullmatch(raw) or _PLACEHOLDER.fullmatch(raw):
                continue
        if end > start:
            if len(result) >= MAX_SPANS:
                raise ValueError('field finding limit exceeded')
            result.append(CredentialSpan(RULES[role], start, end))
    return tuple(result)
