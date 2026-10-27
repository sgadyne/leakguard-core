"""V2 family-held financial/identity context and preset slice."""
from __future__ import annotations

import hashlib
import random

from .corpus_v2 import CorpusCase, DEFAULT_SEED, _case_fingerprint, _derive, _seed_root


_AUX_TEMPLATES = {
    "financial-positive": (
        ("Bank routing credential: VALUE", "US_BANK_NUMBER", True),
        ("Deposit banking transfer field [routing-ref=VALUE]", "US_BANK_NUMBER", True),
        ("Settlement data / bank route key :: VALUE", "US_BANK_NUMBER", True),
        ("Wire-bank destination credential → VALUE", "US_BANK_NUMBER", True),
    ),
    "identity-positive": (
        ("US ITIN filing record ID: VALUE", "US_ITIN", True),
        ("Individual income tax payer key (ITIN) = VALUE", "US_ITIN", True),
        ("Tax filing identity credential :: VALUE", "US_ITIN", True),
        ("US taxpayer record code [filing-ref=VALUE]", "US_ITIN", True),
    ),
    "misleading-numeric-context": (
        ("Telemetry metric shard index#VALUE", "US_BANK_NUMBER", False),
        ("Unrelated order sequence / value VALUE", "US_ITIN", False),
        ("Cache bucket checksum-label → VALUE", "US_BANK_NUMBER", False),
        ("Build artifact row identifier: VALUE", "US_ITIN", False),
    ),
    "distant-context-negative": (
        ("bank transfer routing reference: " + "synthetic ledger event / " * 12 + "VALUE",
         "US_BANK_NUMBER", False),
        ("tax filing identity code: " + "ordinary job record / " * 12 + "VALUE",
         "US_ITIN", False),
        ("bank route marker: " + "fixture-only reconciliation / " * 12 + "VALUE",
         "US_BANK_NUMBER", False),
        ("income tax identifier: " + "synthetic batch metadata / " * 12 + "VALUE",
         "US_ITIN", False),
    ),
}


def _bank(rng: random.Random) -> str:
    return str(rng.randrange(100_000_000, 1_000_000_000))


def _itin(rng: random.Random) -> str:
    middle = rng.choice((*range(50, 66), *range(70, 89), *range(90, 93), *range(94, 100)))
    return f"9{rng.randrange(10)}{rng.randrange(10)}-{middle:02d}-{rng.randrange(10_000):04d}"


def build_auxiliary_cases(seed: int = DEFAULT_SEED) -> list[CorpusCase]:
    """Return 80 dev and 80 held-out cases in 16 actual rendering families."""
    root = hashlib.sha256(f"{_seed_root(seed).hex()}:auxiliary-v2".encode("ascii")).digest()
    rows = []
    serial = 0
    for category, recipes in _AUX_TEMPLATES.items():
        for variant, (template, entity, positive) in enumerate(recipes, 1):
            split = "dev" if variant <= 2 else "holdout"
            family = f"p2-aux-{category}-r{variant}"
            for index in range(10):
                seed_group = f"v2-aux/{family}/{index:02d}"
                rng = random.Random(int.from_bytes(_derive(root, seed_group, 8), "big"))
                value = _bank(rng) if entity == "US_BANK_NUMBER" else _itin(rng)
                text = template.replace("VALUE", value)
                start = text.index(value)
                end = start + len(value)
                normalized = template.replace("VALUE", "<VALUE>")
                rows.append(CorpusCase(
                    case_id=f"v2-aux-{serial:04d}", split=split,
                    template_family=family, seed_group=seed_group,
                    category=category, mode="embedded", text=text,
                    expected_spans=((start, end),) if positive else (),
                    format_outcome="positive" if positive else "negative",
                    actionability="exposed" if positive else "unknown",
                    expected_entity=entity, algorithm=None,
                    development_partition=("train" if variant == 1 else "validation") if split == "dev" else None,
                    logical_path=f"fixtures/v2/context/{family}.txt",
                    negative_kind=None if positive else category,
                    normalized_template=normalized,
                    template_fingerprint=_case_fingerprint(normalized)))
                serial += 1
    return rows
