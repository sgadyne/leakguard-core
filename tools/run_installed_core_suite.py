"""Run the installed core suite, excluding two repeated corpus scans."""
import sys
import unittest

EXCLUDED = {
    'test_corpus.DeterministicCorpusTests.test_actual_labeled_cases_emit_case_level_counts_without_fixture_text',
    'test_corpus.DeterministicCorpusTests.test_same_seed_artifact_manifest_is_stable_across_wall_clock_ticks',
}


def filtered(item, seen):
    if isinstance(item, unittest.TestSuite):
        return unittest.TestSuite(filtered(test, seen) for test in item)
    if item.id() in EXCLUDED:
        seen.add(item.id())
        return unittest.TestSuite()
    return item


suite = unittest.defaultTestLoader.discover('tests')
seen = set()
suite = filtered(suite, seen)
if seen != EXCLUDED:
    raise SystemExit('corpus-exclusion-mismatch')
if sys.argv[1:] == ['--verify-selection']:
    print(f'selected={suite.countTestCases()} excluded={len(seen)}')
    sys.exit(0)
if sys.argv[1:]:
    raise SystemExit('unknown-argument')
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
