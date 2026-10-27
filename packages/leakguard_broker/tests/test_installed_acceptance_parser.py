from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _acceptance_module():
    repository = Path(__file__).resolve().parents[3]
    script = repository / "tools" / "installed_acceptance.py"
    spec = importlib.util.spec_from_file_location("installed_acceptance_test_module", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_json_line_parser_accepts_status_after_piped_admin_prompt():
    parser = _acceptance_module()._json_lines
    status = {
        "unlocked": False,
        "deadline": None,
        "policy_version": "a" * 64,
        "grants": 0,
    }
    output = (
        "LeakGuard admin shell. Type help for commands.\n"
        "leakguard-admin> " + json.dumps(status) + "\n"
        "leakguard-admin> "
    ).encode()
    assert parser(output) == [status]
