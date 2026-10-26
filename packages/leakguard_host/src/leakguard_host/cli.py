"""Small fixed-argv CLI; scanning persistence is supplied by Buddy's session."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .errors import HostError
from .navigation import browse, capabilities, roots
from .services import service_spec
from .ssh import SSHRunner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="leakguard-host")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capabilities")
    commands.add_parser("roots")
    listing = commands.add_parser("browse")
    listing.add_argument("path")
    listing.add_argument("--root")
    listing.add_argument("--cursor")
    listing.add_argument("--limit", type=int, default=100)
    service = commands.add_parser("service-spec")
    service.add_argument("--state-dir", type=Path, required=True)
    service.add_argument("--platform")
    service.add_argument("argv", nargs=argparse.REMAINDER)
    remote = commands.add_parser("ssh-scan")
    remote.add_argument("target")
    remote.add_argument("root")
    remote.add_argument("--python", required=True)
    remote.add_argument("--config-path")
    remote.add_argument("--port", type=int, default=22)
    remote.add_argument("--max-seconds", type=int, default=30)
    remote.add_argument("--max-files", type=int, default=100)
    upload = commands.add_parser("ssh-upload")
    upload.add_argument("target")
    upload.add_argument("artifact", type=Path)
    upload.add_argument("remote_directory")
    upload.add_argument("--sha256", required=True)
    upload.add_argument("--python", default="python3")
    upload.add_argument("--port", type=int, default=22)
    args = parser.parse_args(argv)
    try:
        if args.command == "capabilities":
            result = capabilities()
        elif args.command == "roots":
            result = roots()
        elif args.command == "browse":
            result = browse(args.path, root=args.root, cursor=args.cursor, limit=args.limit)
        elif args.command == "service-spec":
            command = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
            result = service_spec(command, args.state_dir, platform=args.platform)
        elif args.command == "ssh-scan":
            result = SSHRunner(port=args.port).run(args.target, args.root, python=args.python,
                config_path=args.config_path, max_seconds=args.max_seconds, max_files=args.max_files)
        else:
            result = SSHRunner(port=args.port).upload(args.target, args.artifact, args.remote_directory,
                sha256=args.sha256, python=args.python)
        sys.stdout.write(json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n")
        return 0
    except HostError as error:
        sys.stderr.write("LeakGuard host: " + error.code + "\n")
        return 2
    except Exception:
        sys.stderr.write("LeakGuard host: host-operation-failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
