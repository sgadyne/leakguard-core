#!/usr/bin/env python3
"""Execute only the declared redacted corpus cases and emit one JSON summary."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=int(os.environ.get("LEAKGUARD_CORPUS_SEED", "20261025")))
    args = parser.parse_args(argv)
    from test_corpus import run_labeled_corpus

    binary = os.environ.get("LEAKGUARD_GITLEAKS")
    if not binary:
        summary = {"seed": args.seed, "counts": {"labeled_cases": 0, "covered": 0,
                   "uncovered": 0, "failed": 1, "true_positive": 0,
                   "false_positive": 0, "false_negative": 0, "true_negative": 0},
                   "detector_metrics": {"true_positive": 0, "false_positive": 0,
                   "false_negative": 0, "true_negative": 0}, "by_category": {}, "cases": []}
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 1
    try:
        summary = run_labeled_corpus(args.seed, binary)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, GeneratorExit)):
            raise
        summary = {"seed": args.seed, "counts": {"labeled_cases": 0, "covered": 0,
                   "uncovered": 0, "failed": 1, "true_positive": 0,
                   "false_positive": 0, "false_negative": 0, "true_negative": 0},
                   "detector_metrics": {"true_positive": 0, "false_positive": 0,
                   "false_negative": 0, "true_negative": 0}, "by_category": {}, "cases": []}
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 1 if summary["counts"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
