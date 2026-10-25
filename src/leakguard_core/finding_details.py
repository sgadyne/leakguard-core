"""Describe findings without snippets; verify narrowly typed source fingerprints."""
import ast
import bisect
import hashlib
import json
import ntpath
import re
import pathlib

MAX_CONTEXT_BYTES = 1_000_000
_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z')


def json_value_at_line(text, line):
    """Return the exact JSON leaf path/value, including nested metadata contexts."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result

    json.loads(text, object_pairs_hook=unique)
    decoder = json.JSONDecoder()
    matches = []
    newlines = [index for index, char in enumerate(text) if char == '\n']

    def whitespace(index):
        while index < len(text) and text[index].isspace():
            index += 1
        return index

    def walk(index, path):
        index = whitespace(index)
        if text[index] == '{':
            index = whitespace(index + 1)
            while text[index] != '}':
                key, index = decoder.raw_decode(text, index)
                index = whitespace(index)
                index, found = walk(index + 1, path + [key])
                index = whitespace(index)
                if text[index] == ',':
                    index = whitespace(index + 1)
            return index + 1, None
        if text[index] == '[':
            index = whitespace(index + 1); number = 0
            while text[index] != ']':
                index, found = walk(index, path + [number])
                number += 1; index = whitespace(index)
                if text[index] == ',':
                    index = whitespace(index + 1)
            return index + 1, None
        value, end = decoder.raw_decode(text, index)
        first = bisect.bisect_left(newlines, index) + 1
        last = bisect.bisect_left(newlines, end) + 1
        if first <= line <= last:
            matches.append((path, value))
        return end, None

    walk(0, [])
    return matches[0] if len(matches) == 1 else None


def safe_field(parts):
    if all(isinstance(part, int) or isinstance(part, str) and _NAME.fullmatch(part) for part in parts):
        return '.'.join(str(part) for part in parts)
    return None


def describe(finding, data=None, source_reader=None):
    """No value/snippet enters the result. Reader returns sibling module bytes."""
    result = dict(finding)
    rule = result['rule']
    descriptions = {
        'generic-api-key': 'Possible API key/token; heuristic match',
        'literal-client-secret': 'Literal application/client secret',
        'azure-ad-client-secret': 'Azure application secret',
        'literal-password': 'Literal password',
        'xml-password': 'Literal XML configuration password',  # gitleaks:allow -- static display label
    }
    result['info'] = descriptions.get(rule, rule)
    if data is None or len(data) > MAX_CONTEXT_BYTES or ntpath.splitext(result['path'])[1].lower() != '.json':
        return result
    try:
        located = json_value_at_line(data.decode('utf-8-sig'), result['line'])
        if not located:
            return result
        parts, value = located
        field = safe_field(parts)
        if field:
            result['field'] = field
        single_line = result.get('end_line', result['line']) == result['line']
        if rule == 'generic-api-key' and single_line and source_reader and isinstance(value, str) and re.fullmatch('[a-fA-F0-9]{64}', value):
            reference = None
            if len(parts) == 2 and parts[0] == 'source_fingerprints' and isinstance(parts[1], str):
                reference = pathlib.PurePosixPath(parts[1].replace('\\', '/'))
            if reference and not reference.is_absolute() and '..' not in reference.parts and ':' not in str(reference):
                source = source_reader(str(reference))
                if source is not None and len(source) <= MAX_CONTEXT_BYTES and hashlib.sha256(source).hexdigest() == value.lower():
                    result.update(severity='info', classification='verified-file-sha256', info='Verified SHA-256; matches referenced file in this version')
                    return result
        # Never trust a token-looking hex value, a filename, or a review decision
        # alone. This exception needs typed AST context AND matching source bytes.
        if rule != 'generic-api-key' or not single_line or len(parts) != 3 or parts[1] != 'function_ast_sha256':
            return result
        module, _, symbol = parts
        if not isinstance(module, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py', module):
            return result
        if not isinstance(symbol, str) or not symbol.isidentifier() or not isinstance(value, str) or not re.fullmatch('[a-fA-F0-9]{64}', value):
            return result
        if source_reader is None:
            return result
        source = source_reader(module)
        if source is None or len(source) > MAX_CONTEXT_BYTES:
            return result
        tree = ast.parse(source.decode('utf-8-sig'))
        functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol]
        if len(functions) != 1:
            return result
        digest = hashlib.sha256(ast.dump(functions[0]).encode()).hexdigest()
        if digest != value.lower():
            return result
        result.update(severity='info', classification='verified-function-ast-sha256', info='Verified function AST SHA-256; matches sibling source in this version')
    except (ValueError, UnicodeError, IndexError, RecursionError, SyntaxError, OSError):
        pass  # Missing/ambiguous/invalid context never grants an exemption.
    return result
