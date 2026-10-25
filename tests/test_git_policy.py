"""Required Git extraction failures are policy-visible synthetic regressions."""
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import engine


class RequiredDocumentTests(unittest.TestCase):
    def test_direct_guard_rejects_unextractable_document(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-git-') as folder:
            root = Path(folder)
            repo = root / 'repo'
            repo.mkdir()
            subprocess.run(['git', '-c', 'init.templateDir=', 'init', '-q', str(repo)], check=True)
            (repo / 'broken.docx').write_bytes(b'synthetic document')
            subprocess.run(['git', 'add', 'broken.docx'], cwd=repo, check=True)
            real_git = engine.git
            with patch.object(engine, 'STATE', root / 'state'), patch.object(engine, 'git', side_effect=lambda *args, **kwargs: real_git(*args, **({'cwd': repo} | kwargs))), patch.object(engine, 'existing_hook', return_value=0), patch.object(engine, 'engine', return_value=[]), patch.object(engine, 'scan_blob', return_value=([], 'skipped-binary-or-no-text')), patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(engine.git_hook('pre-commit', []), 2)


if __name__ == '__main__':
    unittest.main()
