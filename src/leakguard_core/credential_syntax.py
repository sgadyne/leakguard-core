"""Bounded credential value grammar shared by native and alias detectors.

This classifies syntax, never evaluates code or dereferences a name. Unknown
values remain candidates. Source suffixes select language grammar, not path
exclusions. Native preparation masks only a classified field label: token and
private-key detectors still see every value byte, and source lines are stable.
"""
from __future__ import annotations

import re

MAX_VALUE = 4096
_CODE_SUFFIXES = frozenset(('.py', '.pyi', '.rb', '.js', '.mjs', '.cjs', '.jsx',
    '.ts', '.tsx', '.h', '.m', '.mm', '.swift', '.rs', '.go', '.java', '.c',
    '.cc', '.cpp', '.hpp', '.cs'))
_CODE = re.compile(r'(?:^|[;{}])[ \t]*(?:(?:async[ \t]+)?(?:def|func|function)[ \t]+[A-Za-z_][\w$]*[ \t]*\(|(?:class|interface)[ \t]+[A-Za-z_][\w$]*[ \t]*[{:]|(?:const|let|var)[ \t]+[A-Za-z_][\w$]*[ \t]*=)|(?:self|this)\.$')
_IDENTIFIER = re.compile(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\Z', re.ASCII)
_TYPE = re.compile(r'(?:string|number|boolean|unknown|any|never|void|String|NSString|Boolean|Bool|Data)(?:[?!]|\[\])?\Z')
_OBJC = re.compile(r'\([ \t]*(?:(?:nullable|nonnull|__nullable|__nonnull|const)[ \t]+)?(?:NSString|NSData|id)[ \t]*\*?[ \t]*\)[ \t]*[A-Za-z_][A-Za-z0-9_]*\Z', re.ASCII)
_PROMPT = re.compile(r'<(?:type|enter|insert|provide|your)[ \t]+(?:[A-Za-z][A-Za-z -]{0,100}[ \t]+)?(?:password|passphrase|pin|token|secret)>\Z', re.I)
_FIELD = re.compile(r"(?<![\w.-])(?P<quote>[\"']?)(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,127})(?P=quote)[ \t]*(?P<operator>:=|[:=])[ \t]*", re.ASCII)
_RELEVANT = re.compile(r'password|passwd|passphrase|pwd|token|secret|api[_.-]?key', re.I)


def declaration_prefix_length(raw: str) -> int | None:
    """Consume one recognized type/selector parameter, never an initializer."""
    objc = re.match(_OBJC.pattern.removesuffix(r'\Z') +
                    r'(?=[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*[ \t]*:|[,;)\r\n{}]|$))', raw)
    if objc:
        return objc.end()
    typed = re.match(_TYPE.pattern.removesuffix(r'\Z') +
                     r'(?=[ \t]*(?:[,;)\r\n{]|$))', raw)
    return typed.end() if typed else None


def nonliteral_reason(text: str, key: str, field_start: int, value_start: int,
                      value_end: int, *, quoted: bool, key_quoted: bool = False,
                      operator: str = '=', logical_path: str = '') -> str | None:
    """Return a static reason only for a complete, bounded recognized form."""
    raw = text[value_start:value_end]
    if not raw or len(raw) > MAX_VALUE:
        return None
    suffix = '.' + logical_path.replace('\\', '/').rsplit('/', 1)[-1].rsplit('.', 1)[-1].lower()
    prefix = text[max(text.rfind('\n', 0, field_start) + 1, field_start - 1024):field_start]
    code = suffix in _CODE_SUFFIXES or bool(_CODE.search(prefix))
    if quoted:
        # Apple string tables use quoted labels. Scope this exception to the
        # exact identity mapping, a complete statement, and the .strings type.
        if suffix == '.strings' and key_quoted and raw.casefold() == key.casefold():
            left = text[text.rfind('\n', 0, field_start) + 1:field_start]
            right = text[value_end + 1:text.find('\n', value_end) if '\n' in text[value_end:] else len(text)]
            if not left.strip() and re.fullmatch(r'[ \t]*;[ \t]*', right):
                return 'localization-identity-label'
        return None
    if raw.startswith('='):
        return 'equality-comparison'
    if _PROMPT.fullmatch(raw.strip()):
        return 'credential-prompt-placeholder'
    # Delimiters are grammar only in code. A bare opaque configuration value
    # with a trailing ')' or a dotted name remains reviewable without context.
    scalar = re.sub(r'[ \t]*[)\]:]+[ \t]*$', '', raw) if code else raw
    scalar = scalar.strip()
    if scalar.lower() in {'null', 'none', 'undefined', '~'}:
        return 'typed-null'
    if (scalar.lower() in {'true', 'false'} and
            (code or operator == ':' or suffix == '.toml')):
        return 'typed-boolean'
    if code and scalar == 'nil':
        return 'typed-null'
    if (not key_quoted and operator == ':' and code and
            declaration_prefix_length(raw) is not None):
        return 'type-declaration'
    if code and scalar in {'!0', '!1'}:
        return 'boolean-expression'
    if code and re.fullmatch(r'%(?:[0-9]*\$)?[-+ #0]*[0-9]*(?:\.[0-9]+)?[sdif]', scalar):
        return 'format-placeholder'
    if _IDENTIFIER.fullmatch(scalar) and (code or scalar.startswith(('self.', 'this.'))):
        return 'code-reference'
    return None


def mask_nonliteral_labels(text: str, *, logical_path: str = '') -> str:
    """Hide only syntax labels from heuristic field rules, leaving values intact.

    Native coordinates are intentionally not converted to absolute offsets.
    Labels are ASCII and replacing them preserves Unicode and UTF-8 positions.
    This pass is linear and each candidate value is bounded before parsing.
    """
    spans = []
    for match in _FIELD.finditer(text):
        key = match.group('key')
        if not _RELEVANT.search(key):
            continue
        start = match.end()
        if start >= len(text):
            continue
        quoted = text[start] in '\"\''
        end = start + 1 if quoted else start
        if quoted:
            quote = text[start]
            escaped = False
            while end < len(text) and end - start <= MAX_VALUE and text[end] not in '\r\n':
                char = text[end]
                if char == quote and not escaped:
                    break
                escaped = char == '\\' and not escaped
                end += 1
            if end >= len(text) or text[end] != quote:
                continue
            start += 1
        else:
            while end < len(text) and end - start <= MAX_VALUE and text[end] not in ',;}\r\n':
                end += 1
            while end > start and text[end - 1] in ' \t':
                end -= 1
        if nonliteral_reason(text, key, match.start(), start, end, quoted=quoted,
                key_quoted=bool(match.group('quote')), operator=match.group('operator'),
                logical_path=logical_path):
            spans.append(match.span('key'))
    if not spans:
        return text
    pieces = []; cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        pieces.extend((text[cursor:start], ' ' * (end - start)))
        cursor = end
    pieces.append(text[cursor:])
    return ''.join(pieces)
