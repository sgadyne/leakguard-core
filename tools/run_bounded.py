#!/usr/bin/env python3
"""Run an owned POSIX process tree with a wall-clock deadline."""
import argparse
import os
import signal
import subprocess
import sys
import psutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if os.name != 'posix' or not 1 <= args.seconds <= 3600 or not command:
        parser.error('POSIX command and 1..3600 second deadline required')
    process = subprocess.Popen(command, start_new_session=True)
    def stop_group():
        # Workers can create their own sessions, so snapshot descendants before
        # terminating the leader and signal these owned processes separately.
        try:
            children = psutil.Process(process.pid).children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
        for child in reversed(children):
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        _, alive = psutil.wait_procs(children, timeout=3)
        for child in alive:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        psutil.wait_procs(alive, timeout=2)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    try:
        return process.wait(timeout=args.seconds)
    except subprocess.TimeoutExpired:
        stop_group()
        print('bounded command timed out; gate incomplete', file=sys.stderr)
        return 124
    except KeyboardInterrupt:
        stop_group()
        print('bounded command interrupted; gate incomplete', file=sys.stderr)
        return 130



if __name__ == '__main__':
    raise SystemExit(main())
