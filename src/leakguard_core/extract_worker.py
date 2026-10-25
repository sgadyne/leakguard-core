"""Private bounded parser IPC. Never write parser/input exception text."""
import base64
import json
import sys

from .documents import extract, extract_document
from .extraction import ExtractionLimits


def main():
    if sys.argv[1:] == ['--v2']:
        raw = sys.stdin.buffer.read(80_000_001)
        if len(raw) > 80_000_000:
            return 2
        try:
            request = json.loads(raw)
            if set(request) != {'schema_version', 'format_id', 'limits', 'data'} or request['schema_version'] != 1:
                return 2
            limits = ExtractionLimits(**request['limits'])
            data = base64.b64decode(request['data'], validate=True)
            if len(data) > limits.max_file_bytes:
                return 2
            result = extract_document(data, request['format_id'], limits)
            response = {'format_id': result.format_id, 'disposition': result.disposition,
                        'parts': [{'part_id': part.part_id, 'text': part.text} for part in result.parts],
                        'issues': list(result.issues)}
            output = json.dumps(response, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(output) > limits.max_ipc_bytes:
                return 2
            sys.stdout.buffer.write(output)
            return 0
        except BaseException:
            return 2
    data = sys.stdin.buffer.read(20_971_521)
    if len(data) > 20_971_520:
        return 2
    try:
        parts = list(extract(data, 'document' + sys.argv[1]))
        if len(parts) > 1000 or sum(len(text.encode('utf-8')) for _, text in parts) > 12_000_000:
            return 2
        sys.stdout.buffer.write(json.dumps(parts, ensure_ascii=False).encode('utf-8'))
    except BaseException:
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
