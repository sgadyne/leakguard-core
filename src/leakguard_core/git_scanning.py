"""Bounded immutable index and outgoing-commit acquisition for ScanService."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import time

from . import models as m
from .sources import AcquisitionError, ProofContext, SnapshotInput


MAX_COMMITS = 1000
MAX_DOCUMENT_BLOBS = 100


def git_output(repo, *args, maximum=16_000_000, timeout=45, check=True):
    """Bound parent memory and never forward Git stderr or object contents."""
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.run(['git', *args], cwd=repo, stdout=output, stderr=subprocess.DEVNULL, timeout=max(0.001, timeout))
            output.seek(0)
            data = output.read(maximum + 1)
        if len(data) > maximum:
            raise AcquisitionError('git-range-incomplete')
        if process.returncode and check:
            raise AcquisitionError('git-range-incomplete')
        return process.returncode, data
    except subprocess.TimeoutExpired:
        raise AcquisitionError('budget-exhausted') from None
    except OSError:
        raise AcquisitionError('git-range-incomplete') from None


class GitInputs:
    def __init__(self, repo: Path, request: m.GitRequest, *, limits, cancel=None):
        self.repo = repo.resolve()
        self.request = request
        self.limits = limits
        self.cancel = cancel
        self.deadline = time.monotonic() + limits.deadline_seconds
        self.complete = True
        self.issues = []
        self.index_tree = None
        self.documents = 0

    def _git(self, *args, maximum=16_000_000, check=True):
        if time.monotonic() >= self.deadline or self.cancel and self.cancel():
            raise AcquisitionError('cancelled' if self.cancel and self.cancel() else 'budget-exhausted')
        return git_output(self.repo, *args, maximum=maximum, timeout=min(45, max(0.001, self.deadline - time.monotonic())), check=check)

    def __iter__(self):
        try:
            if self.request.kind is m.GitRequestKind.INDEX:
                self.index_tree = self._git('write-tree', maximum=128)[1].decode('ascii').strip()
                if not _oid(self.index_tree):
                    raise AcquisitionError('git-range-incomplete')
                has_head = self._git('rev-parse', '--verify', 'HEAD', maximum=128, check=False)[0] == 0
                if has_head:
                    names = self._git('diff', '--name-only', '--diff-filter=ACMR', '-z', 'HEAD', self.index_tree)[1]
                else:
                    names = self._git('ls-tree', '-r', '--name-only', '-z', self.index_tree)[1]
                for path in _paths(names):
                    yield self._snapshot(self.index_tree, path, index=True)
            else:
                if self._git('rev-parse', '--is-shallow-repository', maximum=128)[1].strip() == b'true' and any(set(u.local_oid) != {'0'} for u in self.request.updates):
                    raise AcquisitionError('git-range-incomplete')
                seen_revisions = set()
                for update in self.request.updates:
                    local, remote = update.local_oid.lower(), update.remote_oid.lower()
                    if not _oid(local) or not _oid(remote):
                        raise AcquisitionError('git-input-invalid')
                    if set(local) == {'0'}:
                        continue
                    # Validate a commit tip, not an arbitrary object or revision expression.
                    if self._git('cat-file', '-t', local, maximum=128)[1].strip() != b'commit':
                        raise AcquisitionError('git-input-invalid')
                    available = set(remote) != {'0'} and self._git('cat-file', '-e', remote + '^{commit}', check=False)[0] == 0
                    ancestor = available and self._git('merge-base', '--is-ancestor', remote, local, check=False)[0] == 0
                    args = ['rev-list', '--topo-order', '--reverse', '--max-count=' + str(MAX_COMMITS + 1), local]
                    if ancestor:
                        args.append('^' + remote)
                    revisions = self._git(*args, maximum=(MAX_COMMITS + 2) * 66)[1].decode('ascii').splitlines()
                    if len(revisions) > MAX_COMMITS or len(seen_revisions | set(revisions)) > MAX_COMMITS:
                        raise AcquisitionError('git-range-incomplete')
                    for revision in revisions:
                        if revision in seen_revisions:
                            continue
                        seen_revisions.add(revision)
                        # -m includes a merge result's paths changed against any
                        # parent; --root includes every added root-tree path.
                        changed = self._git('diff-tree', '--root', '-m', '--no-commit-id', '--name-only', '--diff-filter=ACMR', '-r', '-z', revision)[1]
                        for path in dict.fromkeys(_paths(changed)):
                            yield self._snapshot(revision, path, index=False)
        except AcquisitionError as error:
            self.complete = False
            self.issues.append(m.CoverageIssue(m.ErrorCode(error.code), required=True))

    def _snapshot(self, revision, path, *, index):
        entry = self._git('rev-parse', '--verify', revision + ':' + path, maximum=128)[1].decode('ascii').strip()
        if not _oid(entry):
            raise AcquisitionError('git-range-incomplete')
        kind = self._git('cat-file', '-t', entry, maximum=128)[1].strip()
        if kind != b'blob':
            raise AcquisitionError('git-range-incomplete')
        size = int(self._git('cat-file', '-s', entry, maximum=128)[1])
        if size > self.limits.max_file_bytes:
            # Keep an explicit per-input required result instead of dropping it.
            source = self._source(path, revision, entry, index)
            self.issues.append(m.CoverageIssue(m.ErrorCode.INPUT_LIMIT, source, required=True))
            self.complete = False
            raise AcquisitionError('input-limit')
        data = self._git('cat-file', 'blob', entry, maximum=self.limits.max_file_bytes)[1]
        if Path(path).suffix.lower() in {'.docx', '.xlsx', '.xlsm', '.pptx', '.pdf', '.msg'}:
            self.documents += 1
            if self.documents > MAX_DOCUMENT_BLOBS:
                raise AcquisitionError('git-range-incomplete')
        parent = PurePosixPath(path).parent

        def sibling(name):
            relative = str(parent / name)
            code, oid = self._git('rev-parse', '--verify', revision + ':' + relative, maximum=128, check=False)
            if code:
                return None
            oid = oid.decode('ascii').strip()
            if not _oid(oid):
                return None
            code, size = self._git('cat-file', '-s', oid, maximum=128, check=False)
            if code or int(size) > 1_000_000:
                return None
            code, content = self._git('cat-file', 'blob', oid, maximum=1_000_000, check=False)
            return content if code == 0 else None

        context = ProofContext(sibling)
        context.prepare(data, path)
        return SnapshotInput(self._source(path, revision, entry, index), data, context)

    def _source(self, path, revision, blob, index):
        return m.SourceRef(m.SourceKind.GIT_INDEX if index else m.SourceKind.GIT_COMMIT, path, str(self.repo), None if index else revision, blob, revision if index else None)

    def valid(self):
        if self.request.kind is not m.GitRequestKind.INDEX or self.index_tree is None:
            return True
        try:
            return self._git('write-tree', maximum=128)[1].decode('ascii').strip() == self.index_tree
        except AcquisitionError:
            return False

    def status(self):
        return {'complete': self.complete, 'issues': tuple(self.issues), 'pending_files': None, 'pending_directories': None}


def _oid(value):
    return isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value)


def _paths(data):
    return (item.decode('utf-8', errors='surrogateescape') for item in data.split(b'\0') if item)


def parse_push(data: bytes):
    if len(data) > 1_000_000:
        raise AcquisitionError('git-input-invalid')
    try:
        text = data.decode('utf-8', errors='strict')
        updates = []
        for line in text.splitlines():
            fields = line.split()
            if len(fields) != 4:
                raise ValueError()
            local_ref, local_oid, remote_ref, remote_oid = fields
            if not all(_oid(value) for value in (local_oid, remote_oid)):
                raise ValueError()
            updates.append(m.RefUpdate(local_ref, local_oid, remote_ref, remote_oid))
        return m.GitRequest(m.GitRequestKind.PUSH, tuple(updates))
    except (ValueError, UnicodeError, TypeError):
        raise AcquisitionError('git-input-invalid') from None
