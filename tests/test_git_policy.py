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
            with patch.object(engine, 'STATE', root / 'state'), patch('pathlib.Path.cwd', return_value=repo), patch.object(engine, 'existing_hook', return_value=0), patch.object(engine.presentation, 'render', return_value='typed incomplete report'), patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(engine.git_hook('pre-commit', []), 2)


if __name__ == '__main__':
    unittest.main()


class GitSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='leakguard-snapshot-')
        self.repo = Path(self.temp.name)
        self.git('-c', 'init.templateDir=', 'init', '-q')
        self.git('config', 'user.name', 'Synthetic')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'core.hooksPath', '/dev/null')

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def test_initial_push_includes_root_and_intermediate_commits(self):
        from leakguard_core import models as m, backends
        (self.repo / 'candidate.txt').write_text('synthetic secret')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic root')
        root = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'candidate.txt').write_text('removed')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic removal')
        head = self.git('rev-parse', 'HEAD').decode().strip()
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            def detect(text, **kwargs):
                return (backends.BackendFinding('literal-password', 1, 1),) if 'secret' in text else ()
            with patch.object(backends, 'detect', side_effect=detect):
                report = service.scan_git(self.repo, request=m.GitRequest(m.GitRequestKind.PUSH, (m.RefUpdate('refs/heads/main', head, 'refs/heads/main', '0' * 40),)), limits=m.ScanLimits(30, 100))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
            self.assertEqual(report.results[0].source.commit, root)
            self.assertEqual(report.counts.findings, 1)
            self.assertTrue(all(result.source.blob_oid for result in report.results))
        finally:
            service.close()

    def test_deletion_only_push_allows_but_malformed_input_is_rejected(self):
        from leakguard_core import models as m
        from leakguard_core.git_scanning import parse_push
        from leakguard_core.sources import AcquisitionError
        with self.assertRaises(AcquisitionError):
            parse_push(b'malformed record\n')
        request = parse_push(('refs/heads/main ' + '0' * 40 + ' refs/heads/main ' + '1' * 40 + '\n').encode())
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            report = service.scan_git(self.repo, request=request, limits=m.ScanLimits(30, 100))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.ALLOW)
            self.assertEqual(report.results, ())
        finally:
            service.close()

    def test_index_change_during_scan_fails_closed(self):
        from leakguard_core import models as m, backends
        (self.repo / 'candidate.txt').write_text('first')
        self.git('add', '.')
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        def detect(text, **kwargs):
            (self.repo / 'candidate.txt').write_text('changed')
            self.git('add', '.')
            return ()
        try:
            with patch.object(backends, 'detect', side_effect=detect):
                report = service.scan_git(self.repo, request=m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 100))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
            self.assertTrue(any(issue.code is m.ErrorCode.INPUT_CHANGED for issue in report.issues))
        finally:
            service.close()


class EmptyGitReportTests(unittest.TestCase):
    setUp = GitSnapshotTests.setUp
    tearDown = GitSnapshotTests.tearDown
    git = GitSnapshotTests.git
    def test_empty_git_report_is_latest_for_the_explicit_repository(self):
        from leakguard_core import models as m
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-empty-report-') as folder:
                store = store_type(folder) if store_type is SQLiteScanStore else store_type()
                service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
                try:
                    report = service.scan_git(self.repo, request=m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 10))
                    self.assertEqual(report.results, ())
                    self.assertEqual(report.decision.verdict, m.DecisionVerdict.ALLOW)
                    self.assertEqual(store.latest_report(str(self.repo.resolve())).run_id, report.run_id)
                finally:
                    service.close(); store.close()


class OriginalGitObjectTests(unittest.TestCase):
    setUp = GitSnapshotTests.setUp
    tearDown = GitSnapshotTests.tearDown
    git = GitSnapshotTests.git

    def scan_tip(self, tip):
        from leakguard_core import models as m
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            return service.scan_git(self.repo, request=m.GitRequest(m.GitRequestKind.PUSH, (m.RefUpdate('refs/heads/main', tip, 'refs/heads/main', '0' * 40),)), limits=m.ScanLimits(30, 100))
        finally:
            service.close()

    def test_replacement_ref_cannot_hide_original_commit_secret(self):
        from leakguard_core import models as m
        (self.repo / 'candidate.txt').write_text('password = "SyntheticOnlyOriginalM7kQ2vR9"\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic original')
        original = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'candidate.txt').write_text('ordinary text\n')
        self.git('add', '.')
        tree = self.git('write-tree').decode().strip()
        replacement = self.git('commit-tree', tree, '-m', 'synthetic replacement').decode().strip()
        self.git('replace', original, replacement)
        # Demonstrate that ordinary local plumbing observes the clean replacement.
        self.assertEqual(self.git('show', original + ':candidate.txt'), b'ordinary text\n')
        report = self.scan_tip(original)
        self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
        self.assertTrue(any(f.rule == 'literal-password' for result in report.results for f in result.findings))
        self.assertTrue(any(result.source.commit == original for result in report.results))

    def test_local_graft_cannot_hide_intermediate_secret_commit(self):
        from leakguard_core import models as m
        (self.repo / 'candidate.txt').write_text('password = "SyntheticOnlyGraftedM7kQ2vR9"\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic root')
        original = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'candidate.txt').write_text('ordinary text\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic clean child')
        tip = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / '.git' / 'info').mkdir(exist_ok=True)
        (self.repo / '.git' / 'info' / 'grafts').write_text(tip + '\n')
        self.assertEqual(self.git('rev-list', tip).decode().splitlines(), [tip])
        report = self.scan_tip(tip)
        self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
        self.assertTrue(any(result.source.commit == original for result in report.results))

    def test_annotated_tag_peels_to_commit_and_noncommit_tag_fails_closed(self):
        from leakguard_core import models as m
        (self.repo / 'candidate.txt').write_text('ordinary text\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic root')
        self.git('tag', '-a', 'synthetic-tag', '-m', 'synthetic annotation')
        tip = self.git('rev-parse', 'synthetic-tag').decode().strip()
        report = self.scan_tip(tip)
        self.assertEqual(report.decision.verdict, m.DecisionVerdict.ALLOW)
        self.assertTrue(report.results)
        blob = self.git('rev-parse', 'HEAD:candidate.txt').decode().strip()
        self.git('tag', '-a', 'synthetic-blob-tag', blob, '-m', 'synthetic blob annotation')
        report = self.scan_tip(self.git('rev-parse', 'synthetic-blob-tag').decode().strip())
        self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
        self.assertTrue(any(issue.code is m.ErrorCode.GIT_INPUT_INVALID for issue in report.issues))


class GitPathIdentityTests(unittest.TestCase):
    setUp = GitSnapshotTests.setUp
    tearDown = GitSnapshotTests.tearDown
    git = GitSnapshotTests.git

    def test_subdirectory_request_uses_repository_root_without_resetting_deadline(self):
        from leakguard_core import models as m
        from leakguard_core.git_scanning import GitInputs
        child = self.repo / 'subdirectory'; child.mkdir()
        (child / 'candidate.txt').write_text('ordinary text\n')
        self.git('add', '.')
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            report = service.scan_git(child, request=m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 10))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.ALLOW)
            self.assertEqual(report.results[0].source.repository, str(self.repo.resolve()))
            self.assertEqual(report.results[0].source.path, 'subdirectory/candidate.txt')
            self.assertIsNone(service.store._deadlines.get(__import__('threading').get_ident()))
            with patch('leakguard_core.git_scanning.repository_root', side_effect=lambda repo, **kwargs: (setattr(self, 'discovery_deadline', kwargs['deadline']) or self.repo)):
                session = GitInputs(child, m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 10))
            self.assertEqual(session.deadline, self.discovery_deadline)
        finally:
            service.close()

    @unittest.skipIf(__import__('os').name == 'nt', 'POSIX pathname bytes')
    def test_trailing_space_newline_and_undecodable_root_bytes_are_preserved(self):
        import os
        from leakguard_core import models as m
        from leakguard_core.git_scanning import path_output
        name = os.fsdecode(b'repository-\xff \n')
        moved = self.repo / name; moved.mkdir()
        (self.repo / '.git').rename(moved / '.git')
        self.repo = moved
        (self.repo / 'candidate.txt').write_text('ordinary text\n')
        self.git('add', '.')
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            report = service.scan_git(self.repo, request=m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 10))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.ALLOW)
            self.assertEqual(report.results[0].source.repository, str(self.repo.resolve()))
            self.assertEqual(path_output(os.fsencode(str(self.repo)) + b'\n'), str(self.repo))
            self.assertIn('\\udcff', report.to_json())
        finally:
            service.close()

    @unittest.skipIf(__import__('os').name == 'nt', 'POSIX shell and pathname semantics')
    def test_existing_hook_path_keeps_its_trailing_newline(self):
        directory = self.repo / 'hooks \n'; directory.mkdir()
        (directory / 'pre-commit.before-leakguard').write_text('#!/bin/sh\nexit 7\n')
        self.git('config', 'core.hooksPath', str(directory))
        self.assertEqual(engine.existing_hook(self.repo, 'pre-commit', (), b''), 7)


class GitContextEnvironmentTests(unittest.TestCase):
    def test_git_preserves_user_config_discovery_without_expanding_other_workers(self):
        import os
        from types import SimpleNamespace
        from leakguard_core.git_scanning import git_output, repository_root
        from leakguard_core.sources import AcquisitionError
        captured = {}
        def worker(*args, **kwargs):
            captured.update(kwargs['env'])
            return SimpleNamespace(returncode=0, stdout=b'/synthetic/repository\n')
        with tempfile.TemporaryDirectory(prefix='leakguard-private-xdg-') as folder, patch.dict(os.environ, {'XDG_CONFIG_HOME': folder}), patch('leakguard_core._supervision.run_worker', side_effect=worker):
            git_output(Path(folder), 'rev-parse', '--show-toplevel')
            self.assertEqual(captured.get('HOME'), os.environ.get('HOME'))
            self.assertEqual(captured['XDG_CONFIG_HOME'], folder)
            self.assertEqual(captured['GIT_NO_REPLACE_OBJECTS'], '1')
            self.assertEqual(captured['GIT_GRAFT_FILE'], os.devnull)
            with self.assertRaises(AcquisitionError) as failure:
                repository_root(Path(folder), deadline=__import__('time').monotonic() + 5, cancel=lambda: True)
            self.assertEqual(failure.exception.code, 'cancelled')


class InventoryRulePolicyTests(unittest.TestCase):
    setUp = GitSnapshotTests.setUp
    tearDown = GitSnapshotTests.tearDown
    git = GitSnapshotTests.git

    def test_companion_review_rule_cannot_downgrade_actual_index_credential(self):
        from leakguard_core import models as m
        candidate = self.repo / 'candidate.txt'
        candidate.write_text('client_secret = "SyntheticOnlyInventoryRuleM7kQ2vR9"\n')
        self.git('add', '.')
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE), 'review_only_rules': ['literal-client-secret'], 'audit_scopes': {'local': str(self.repo)}, 'profiles': {'companion': {'sources': ['local']}}})
        try:
            report = service.scan_git(self.repo, request=m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 10))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
            matching = [f for r in report.results for f in r.findings if f.rule == 'literal-client-secret']
            self.assertEqual(len(matching), 1)
            self.assertEqual((matching[0].detector_severity, matching[0].severity), (m.DetectorSeverity.BLOCK, m.FindingSeverity.BLOCK))
            inventory = service.scan((m.FileInput(candidate),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10), use_cache=False)
            finding = inventory.results[0].findings[0]
            self.assertEqual((finding.detector_severity, finding.severity), (m.DetectorSeverity.BLOCK, m.FindingSeverity.REVIEW))
        finally:
            service.close()

    def test_explicit_git_mode_for_bytes_and_plugin_blocks_keeps_native_severity(self):
        from leakguard_core import models as m, backends, plugins
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE), 'review_only_rules': ['literal-client-secret']})
        try:
            with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-client-secret', 1, 1),)):
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=m.ScanPolicy.git(), limits=m.ScanLimits(30, 1), use_cache=False)
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
            service._plugins = [object()]
            service._cache_eligible = False
            for policy in (m.ScanPolicy.inventory(), m.ScanPolicy.git()):
                with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-client-secret', 1, 1),)), patch.object(plugins, 'detect', return_value=(plugins.Finding('literal-client-secret', 1, 'block'),)):
                    report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=policy, limits=m.ScanLimits(30, 1), use_cache=False)
                finding = report.results[0].findings[0]
                self.assertEqual((finding.detector_severity, finding.severity), (m.DetectorSeverity.BLOCK, m.FindingSeverity.BLOCK))
                if policy.mode is m.ScanMode.INVENTORY:
                    self.assertEqual(finding.detector_id, 'plugin-legacy')
        finally:
            service.close()


class FinalGitAcceptanceTests(unittest.TestCase):
    setUp = GitSnapshotTests.setUp
    tearDown = GitSnapshotTests.tearDown
    git = GitSnapshotTests.git

    def test_installed_pre_commit_ignores_repository_core_package_spoof(self):
        from leakguard_core import hooks
        marker = 'SyntheticOnlySpoofedHookM7kQ2vR9xL4nD8'
        (self.repo / 'candidate.txt').write_text('client_secret = "' + marker + '"\n')
        spoof = self.repo / 'leakguard_core'; spoof.mkdir()
        (spoof / '__init__.py').write_text('')
        (spoof / '__main__.py').write_text("from pathlib import Path\nPath('.spoofed-scanner-ran').write_text('executed')\nraise SystemExit(0)\n")
        self.git('add', 'candidate.txt')
        self.git('config', 'core.hooksPath', '.git/hooks')
        hooks.install_at(self.repo / '.git' / 'hooks')
        committed = subprocess.run(['git', 'commit', '-qm', 'synthetic spoofed scanner'], cwd=self.repo, capture_output=True)
        self.assertFalse((self.repo / '.spoofed-scanner-ran').exists())
        self.assertNotEqual(committed.returncode, 0)
        self.assertIn(b'LeakGuard blocked', committed.stderr)
        self.assertNotIn(marker.encode(), committed.stdout + committed.stderr)

    def test_installed_pre_commit_ignores_future_pythonpath_spoof(self):
        import os
        from leakguard_core import hooks
        marker = 'SyntheticOnlyInjectedHookM7kQ2vR9xL4nD8'
        (self.repo / 'candidate.txt').write_text('client_secret = "' + marker + '"\n')
        self.git('add', 'candidate.txt')
        self.git('config', 'core.hooksPath', '.git/hooks')
        hooks.install_at(self.repo / '.git' / 'hooks')
        injected = self.repo / 'future-pythonpath'; injected.mkdir()
        spoof = injected / 'leakguard_core'; spoof.mkdir()
        (spoof / '__init__.py').write_text('')
        sentinel = self.repo / '.pythonpath-spoof-ran'
        (spoof / '__main__.py').write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ").write_text('executed')\nraise SystemExit(0)\n")
        committed = subprocess.run(['git', 'commit', '-qm', 'synthetic injected scanner'], cwd=self.repo, capture_output=True, env={**os.environ, 'PYTHONPATH': str(injected)})
        self.assertFalse(sentinel.exists())
        self.assertNotEqual(committed.returncode, 0)
        self.assertIn(b'LeakGuard blocked', committed.stderr)
        self.assertNotIn(marker.encode(), committed.stdout + committed.stderr)

    def test_installed_hook_preserves_fixed_unicode_extension_path(self):
        import json
        import os
        import sys
        from leakguard_core import hooks
        with tempfile.TemporaryDirectory(prefix="leakguard-trusted-'é'-") as folder:
            extension = Path(folder)
            (extension / 'trusted_hook_fixture.py').write_text("API_VERSION=1\nfrom leakguard_core.plugins import Finding\nclass Detector:\n def detect(self,text,path,part): return [Finding('synthetic-hook-plugin',1,'block')]\ndef create_plugin(options): return Detector()\n")
            config = extension / 'config.json'
            config.write_text(json.dumps({'plugins': [{'module': 'trusted_hook_fixture'}]}))
            (self.repo / 'candidate.txt').write_text('ordinary clean content\n')
            self.git('add', 'candidate.txt')
            self.git('config', 'core.hooksPath', '.git/hooks')
            with patch.object(sys, 'path', [*sys.path, str(self.repo), '', str(extension)]):
                captured = hooks._trusted_paths(self.repo / '.git' / 'hooks')
                self.assertNotIn(str(self.repo.resolve()), captured)
                self.assertNotIn(str(Path.cwd().resolve()), captured)
                self.assertIn(str(extension.resolve()), captured)
                hooks.install_at(self.repo / '.git' / 'hooks')
            committed = subprocess.run(['git', 'commit', '-qm', 'synthetic trusted extension'], cwd=self.repo, capture_output=True, env={**os.environ, 'LEAKGUARD_CONFIG': str(config)})
            self.assertNotEqual(committed.returncode, 0)
            self.assertIn(b'synthetic-hook-plugin', committed.stderr)
            self.assertIn(b'LeakGuard blocked', committed.stderr)

    def test_installed_pre_push_rejects_secret_in_actual_orphan_root(self):
        from leakguard_core import hooks
        marker = 'SyntheticOnlyOrphanRootM7kQ2vR9xL4nD8'
        (self.repo / 'candidate.txt').write_text('client_secret = "' + marker + '"\n')
        self.git('add', 'candidate.txt')
        self.git('commit', '--no-verify', '-qm', 'synthetic orphan root')
        self.git('config', 'core.hooksPath', '.git/hooks')
        hooks.install_at(self.repo / '.git' / 'hooks')
        if __import__('os').name != 'nt':
            self.assertTrue((self.repo / '.git' / 'hooks' / 'pre-push').stat().st_mode & 0o111)
        bare = self.repo / 'explicit-private-remote.git'
        made = subprocess.run(['git', '-c', 'init.templateDir=', 'init', '--bare', '-q', str(bare)], capture_output=True)
        self.assertEqual(made.returncode, 0)
        pushed = subprocess.run(['git', 'push', str(bare), 'HEAD:refs/heads/synthetic-root'], cwd=self.repo, capture_output=True)
        self.assertNotEqual(pushed.returncode, 0)
        self.assertIn(b'LeakGuard blocked', pushed.stderr)
        self.assertNotIn(marker.encode(), pushed.stdout + pushed.stderr)
        absent = subprocess.run(['git', '--git-dir=' + str(bare), 'rev-parse', '--verify', 'refs/heads/synthetic-root'], capture_output=True)
        self.assertNotEqual(absent.returncode, 0)

    def test_installed_pre_push_preserves_backup_arguments_stdin_and_failure(self):
        from leakguard_core import hooks
        (self.repo / 'candidate.txt').write_text('ordinary clean content\n')
        self.git('add', 'candidate.txt')
        self.git('commit', '--no-verify', '-qm', 'synthetic clean root')
        head = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('config', 'core.hooksPath', '.git/hooks')
        directory = self.repo / '.git' / 'hooks'; directory.mkdir(exist_ok=True)
        (directory / 'pre-push').write_text('#!/bin/sh\nprintf "%s\\n" "$1" "$2" > .chained-args\ncat > .chained-input\nexit 7\n')
        hooks.install_at(directory)
        bare = self.repo / 'explicit-private-remote.git'
        made = subprocess.run(['git', '-c', 'init.templateDir=', 'init', '--bare', '-q', str(bare)], capture_output=True)
        self.assertEqual(made.returncode, 0)
        pushed = subprocess.run(['git', 'push', str(bare), 'HEAD:refs/heads/synthetic-clean'], cwd=self.repo, capture_output=True)
        self.assertNotEqual(pushed.returncode, 0)
        arguments = (self.repo / '.chained-args').read_text().splitlines()
        self.assertEqual([Path(value).resolve() for value in arguments], [bare.resolve(), bare.resolve()])
        fields = (self.repo / '.chained-input').read_text().split()
        self.assertEqual(len(fields), 4)
        self.assertEqual(fields[1:], [head, 'refs/heads/synthetic-clean', '0' * len(head)])
        absent = subprocess.run(['git', '--git-dir=' + str(bare), 'rev-parse', '--verify', 'refs/heads/synthetic-clean'], capture_output=True)
        self.assertNotEqual(absent.returncode, 0)

    def test_actual_production_commit_count_bound_fails_closed(self):
        from leakguard_core import models as m
        from leakguard_core.git_scanning import MAX_COMMITS
        chunks = []
        for number in range(MAX_COMMITS + 1):
            message = ('synthetic bounded history ' + str(number)).encode()
            chunks.append(b'commit refs/heads/synthetic-bound\ncommitter Synthetic <synthetic@example.invalid> 1700000000 +0000\ndata ' + str(len(message)).encode() + b'\n' + message + b'\n\n')
        imported = subprocess.run(['git', 'fast-import', '--quiet'], cwd=self.repo, input=b''.join(chunks) + b'done\n', capture_output=True)
        self.assertEqual(imported.returncode, 0)
        head = self.git('rev-parse', 'refs/heads/synthetic-bound').decode().strip()
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            request = m.GitRequest(m.GitRequestKind.PUSH, (m.RefUpdate('refs/heads/synthetic-bound', head, 'refs/heads/synthetic-bound', '0' * len(head)),))
            report = service.scan_git(self.repo, request=request, limits=m.ScanLimits(30, 10))
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
            self.assertTrue(any(issue.code is m.ErrorCode.GIT_RANGE_INCOMPLETE for issue in report.issues))
            self.assertEqual(report.results, ())
        finally:
            service.close()
