#!/usr/bin/env python3
"""Exercise installed runtime upgrade and rollback on disposable synthetic Git data.

Inputs are independently installed environments. The private example must be
installed in both. State snapshots are separate: new state is never given to old
code. This script does not build, install, or alter either environment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-python', type=Path, required=True)
    parser.add_argument('--new-python', type=Path, required=True)
    parser.add_argument('--backend', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.output_dir.absolute()
    if out.exists():
        raise SystemExit('output directory already exists')
    out.mkdir(mode=0o700, parents=True)
    os.umask(0o077)
    env = {k: v for k, v in os.environ.items() if k not in {
        'PYTHONPATH', 'PYTHONHOME', 'LEAKGUARD_CONFIG', 'LEAKGUARD_STATE_DIR', 'LEAKGUARD_GITLEAKS'
    } and not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    repo, remote = out / 'repo', out / 'remote.git'
    repo.mkdir()
    canary = 'synthetic-value-6f02781ba492e3dd'
    captured = []
    def run(command, *, cwd=out, expected=0):
        result = subprocess.run([str(x) for x in command], cwd=cwd, env=env,
                                text=True, capture_output=True, timeout=180)
        captured.append(result.stdout + result.stderr)
        if result.returncode != expected:
            raise RuntimeError('command status %s expected %s: %s' %
                               (result.returncode, expected, Path(command[0]).name))
        if canary in captured[-1]:
            raise RuntimeError('synthetic value appeared in output')
        return result
    def git(*command, expected=0):
        return run(['git', *command], cwd=repo, expected=expected)
    git('init', '-q')
    git('config', 'user.name', 'Synthetic')
    git('config', 'user.email', 'synthetic@example.invalid')
    run(['git', 'init', '--bare', '-q', remote])
    git('remote', 'add', 'origin', remote)
    config = out / 'config.json'
    config.write_text(json.dumps({'gitleaks_executable': str(args.backend.absolute()),
        'worker_policy': 'strict', 'plugins': [
            {'module': 'credential_detector.plugin', 'options': {}},
            {'module': 'private_credential_pack.plugin', 'options': {}}]}) + '\n')
    config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
    chain_log = out / 'chain.log'
    original = '#!/bin/sh\nprintf "chain\\n" >> "' + str(chain_log) + '"\n'
    hook = repo / '.git/hooks/pre-commit'
    hook.write_text(original)
    hook.chmod(0o755)
    old_state, new_state = out / 'old-state', out / 'new-state'
    def install(python, state):
        run([python, '-I', '-m', 'leakguard_core.hooks', 'install', repo,
             '--config', config, '--state-dir', state])
        assert (repo / '.git/hooks/pre-commit.before-leakguard').read_text() == original
        assert str(python.absolute()) in hook.read_text()
        assert hashlib.sha256(config.read_bytes()).hexdigest() == config_hash
    def exercise(label):
        (repo / (label + '-clean.txt')).write_text('synthetic clean\n')
        git('add', label + '-clean.txt')
        git('commit', '-qm', label + ' clean')
        git('push', '-q', 'origin', 'HEAD:refs/heads/main')
        (repo / (label + '-blocked.txt')).write_text('acme_deploy_key = ' + canary + '\n')
        git('add', label + '-blocked.txt')
        git('commit', '-qm', label + ' blocked', expected=1)
        # Force a local commit only to exercise the real pre-push guard.
        git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', label + ' forced')
        git('push', '-q', 'origin', 'HEAD:refs/heads/main', expected=1)
        git('reset', '--hard', 'HEAD~1')
    install(args.old_python, old_state)
    exercise('old')
    if old_state.exists():
        shutil.copytree(old_state, out / 'old-state-snapshot')
    else:
        (out / 'old-state-snapshot').mkdir()
    install(args.new_python, new_state)
    exercise('new')
    # Reinstall old hooks with a preserved old snapshot, not newly written state.
    restored = out / 'restored-old-state'
    shutil.copytree(out / 'old-state-snapshot', restored)
    install(args.old_python, restored)
    exercise('rollback')
    run([args.old_python, '-I', '-m', 'leakguard_core.hooks', 'uninstall', repo])
    assert hook.read_text() == original
    assert len(chain_log.read_text().splitlines()) == 6
    for state in (old_state, new_state, restored):
        if state.exists():
            for path in state.rglob('*'):
                if path.is_file() and canary.encode() in path.read_bytes():
                    raise RuntimeError('synthetic value appeared in state')
    receipt = {'synthetic_only': True, 'configuration_unchanged': True,
               'firm_example_preserved': True, 'original_hook_chain_restored': True,
               'old_new_rollback_commit_and_push': 'passed',
               'separate_state_snapshots': True, 'outputs_and_state_value_free': True}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
