"""Console entry point for the loopback-only Password Buddy app."""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="leakguard-buddy", description="Start the local LeakGuard browser companion")
    parser.add_argument("command", nargs="?", choices=("open",), help="open the one-time browser session for a running service")
    parser.add_argument("--config", type=Path, help="private LeakGuard config file")
    parser.add_argument("--state-dir", type=Path, help="private per-user runtime state directory")
    parser.add_argument("--no-browser", action="store_true", help="run as a local service without opening a browser")
    args = parser.parse_args(argv)
    if args.command == "open":
        from .server import open_existing
        if not open_existing(args.state_dir):
            print("Password Buddy is not running, or its browser session has already been opened.")
            return 1
        return 0
    if args.config is not None:
        os.environ["LEAKGUARD_CONFIG"] = str(args.config.expanduser().absolute())
    if args.state_dir is not None:
        os.environ["LEAKGUARD_STATE_DIR"] = str(args.state_dir.expanduser().absolute())
    from .backend import BuddyBackend
    from .server import serve_forever

    from .ownership import ProfileInUse
    try:
        backend = BuddyBackend(state_dir=args.state_dir, config_path=args.config)
    except ProfileInUse:
        print("Password Buddy cannot start: profile-in-use.")
        return 1
    bootstrap_file = backend.state_dir / "buddy-launch.url"
    serve_forever(backend, open_browser=not args.no_browser, bootstrap_file=bootstrap_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
