"""Private local IPC worker; stdout is consumed in memory, never a findings log."""
import json
import sys
from .documents import extract

if __name__ == '__main__':
    data = sys.stdin.buffer.read(20_971_521)
    if len(data) > 20_971_520:
        sys.exit(2)
    try:
        parts = list(extract(data, 'document' + sys.argv[1]))
        if sum(len(text.encode('utf-8')) for _, text in parts) > 12_000_000:
            sys.exit(2)
        sys.stdout.buffer.write(json.dumps(parts, ensure_ascii=False).encode('utf-8'))
    except Exception:
        sys.exit(2)
