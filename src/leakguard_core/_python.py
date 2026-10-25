"""Fixed isolated launch of the already selected core installation.

Python's normal ``-m`` search includes the caller's working directory. Neither
an input repository nor a later PYTHONPATH value may select the scanner used by
an installed hook or a built-in parser. Explicit extension search paths may be
captured by an installer; they follow the interpreter's standard/site paths.
"""
from __future__ import annotations

from itertools import islice
import json
from pathlib import Path
import sys


_LAUNCH = '''import json, runpy, sys
root, module, paths = sys.argv[1:4]
sys.argv = [module, *sys.argv[4:]]
sys.path.insert(0, root)
sys.path.extend(json.loads(paths))
runpy.run_module(module, run_name='__main__', alter_sys=True)
'''


def core_command(module, *args, executable=None, search_paths=()):
    if module not in {'leakguard_core', 'leakguard_core.extract_worker', 'leakguard_core.plugin_worker'}:
        raise ValueError('configuration-invalid')
    paths = tuple(islice(iter(search_paths), 257))
    if len(paths) > 256 or any(type(path) is not str or not path or '\x00' in path
                               or len(path) > 4096 or not Path(path).is_absolute()
                               for path in paths):
        raise ValueError('configuration-invalid')
    encoded = json.dumps(paths, ensure_ascii=True, separators=(',', ':'))
    if len(encoded) > 65536:
        raise ValueError('configuration-invalid')
    return [str(executable or sys.executable), '-I', '-X', 'utf8', '-c', _LAUNCH,
            str(Path(__file__).resolve().parent.parent), module, encoded, *args]
