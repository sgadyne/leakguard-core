"""Exercise comparison privacy, incomplete scans and source-change rejection."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'tools/compare_selected_scope.py'
CANARY = 'synthetic-value-that-must-never-appear'


def executable(path, mode):
    path.write_text('''#!%s
import json,sys
paths = sys.argv[sys.argv.index('--')+1:]
mode = %r
if mode == 'change':
    open(paths[0], 'a').write('changed')
findings = [] if mode == 'candidate' else [{'rule':'literal-password', 'detector_id':'gitleaks', 'severity':'block', 'part_id':'text', 'start_line':1, 'end_line':1, 'snippet':%r}]
result = [{'source':{'path':p}, 'outcome':'scanned', 'findings':findings} for p in paths]
counts = {'scanned':len(paths), 'reused':0, 'skipped':0, 'errors':int(mode=='incomplete'), 'interrupted':0, 'omitted_results':0, 'incomplete_results':0}
print(json.dumps({'counts':counts, 'coverage':{'enumeration_complete':True, 'required_complete':True}, 'results':result}))
print(%r, file=sys.stderr)
''' % (sys.executable, mode, CANARY, CANARY), encoding='utf-8')
    path.chmod(0o700)


class CompareScopeTests(unittest.TestCase):
    def test_private_comparison_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            source, config = root/'source.txt', root/'config.json'
            source.write_text(CANARY)
            config.write_text('{}')
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps({'files':[{'path':str(source), 'size':source.stat().st_size,
                'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]}))
            baseline, candidate = root/'old', root/'new'
            executable(baseline, 'baseline')
            executable(candidate, 'candidate')
            cmd = [sys.executable, str(TOOL), '--root', str(root), '--expected-count', '1', '--manifest', str(manifest), '--baseline', str(baseline), '--baseline-config', str(config), '--candidate', str(candidate), '--candidate-config', str(config)]
            completed = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0)
            self.assertNotIn(CANARY, completed.stdout + completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual((result['baseline_count'], result['candidate_count']), (1, 0))
            self.assertEqual(result['removed'][0]['rule'], 'literal-password')
            self.assertTrue(result['scope_unchanged'])
            for mode in ('incomplete', 'change'):
                executable(candidate, mode)
                completed = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 2)
                self.assertNotIn(CANARY, completed.stdout + completed.stderr)
                self.assertEqual(completed.stdout, '')


if __name__ == '__main__':
    unittest.main()
