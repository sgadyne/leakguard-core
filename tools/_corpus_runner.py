"""Internal stdout-counting test runner for the bounded corpus receipt tool."""
from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
suite = unittest.defaultTestLoader.discover(
    start_dir=str(ROOT / "tests"), pattern="test_corpus.py",
)
result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
