"""Coverage of every shipped field alias against synthetic literals and controls."""
import json
from pathlib import Path

import pytest

from credential_detector.aliases import load_packs, normalize_key
from credential_detector.engine import scan_fields

ROOT = Path(__file__).parent
CASES = json.loads((ROOT / 'fixtures' / 'pack-alias-cases.json').read_text())
GROUPS = ('common', 'cloud', 'developer-ci', 'data-messaging', 'saas-ai', 'key-material')
PACK = load_packs('credential_detector.resources', tuple(f'{group}.json' for group in GROUPS))


def test_fixture_inventory_matches_all_bundled_aliases():
    resources = ROOT.parent / 'src' / 'credential_detector' / 'resources'
    inventory = []
    for group in GROUPS:
        doc = json.loads((resources / f'{group}.json').read_text())
        assert doc['pack_id'] == group
        for item in doc['aliases']:
            assert item['group'] == group
            inventory.append((group, item['name'], 'credential-' + item['role']))
    assert len(CASES) == len(inventory) == len(PACK.aliases)
    assert sorted(inventory) == sorted((c['group'], c['name'], c['rule']) for c in CASES)
    assert len({normalize_key(c['name']) for c in CASES}) == len(CASES)


@pytest.mark.parametrize('case', CASES, ids=[c['name'] for c in CASES])
def test_each_alias_literal_and_full_key_boundary(case):
    positive = case['positive']
    spans = scan_fields(positive, PACK)
    assert [(s.rule, positive[s.start:s.end]) for s in spans] == [(case['rule'], 'x')]
    assert scan_fields(case['negative'], PACK) == ()
    assert scan_fields(f"{case['name']}=$ENV_SECRET", PACK) == ()
    quoted = f"{case['name']}='$ENV_SECRET'"
    spans = scan_fields(quoted, PACK)
    assert [(s.rule, quoted[s.start:s.end]) for s in spans] == [(case['rule'], '$ENV_SECRET')]


def test_alias_separators_case_and_unlabelled_password():
    assert len(scan_fields('API-KEY: "x"', PACK)) == 1
    assert len(scan_fields('api.key: "x"', PACK)) == 1
    assert scan_fields('unlabelled text x', PACK) == ()
