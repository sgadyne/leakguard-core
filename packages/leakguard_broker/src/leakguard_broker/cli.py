"""Command line client for the LeakGuard credential broker."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
from pathlib import Path
import sys

from .client import BrokerClient, BrokerClientError


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: invalid command line\n")


def _pair(value: str, *, separator: str = "=") -> list[str]:
    if type(value) is not str or separator not in value:
        raise BrokerClientError("request-invalid")
    key, item = value.split(separator, 1)
    if not key:
        raise BrokerClientError("request-invalid")
    return [key, item]


def _read_body(path: Path | None) -> bytes:
    if path is None:
        return b""
    try:
        stream = sys.stdin.buffer if str(path) == "-" else path.open("rb")
        with stream if stream is not sys.stdin.buffer else _no_close(stream) as source:
            body = source.read(1024 * 1024 + 1)
    except OSError:
        raise BrokerClientError("input-unavailable") from None
    if len(body) > 1024 * 1024:
        raise BrokerClientError("request-invalid")
    return body


class _no_close:
    """Context manager for stdin, which the CLI must leave open."""

    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        return self.stream

    def __exit__(self, *exc):
        return False


def _parser() -> _Parser:
    parser = _Parser(prog="leakguard-agent", description=__doc__)
    parser.add_argument("--url", required=True, help="broker HTTPS origin")
    parser.add_argument("--ca", required=True, help="broker CA certificate file")
    parser.add_argument("--cert", required=True, help="agent certificate file")
    parser.add_argument("--key", required=True, help="agent private key file")
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory", help="find permitted binding metadata")
    inventory.add_argument("--grant", required=True)
    inventory.add_argument("--label")
    inventory.add_argument("--tag", action="append", dest="tags")
    inventory.add_argument("--environment")
    inventory.add_argument("--cursor")
    inventory.add_argument("--limit", type=int, default=20)
    request = commands.add_parser("request", help="make a scoped upstream request")
    request.add_argument("--grant", required=True)
    request.add_argument("--binding", required=True)
    request.add_argument("--method", required=True)
    request.add_argument("--path", required=True)
    request.add_argument("--query", action="append", default=[], metavar="KEY=VALUE")
    request.add_argument("--header", action="append", default=[], metavar="NAME=VALUE")
    request.add_argument("--body-file", type=Path, help="bounded request body; use - for stdin")
    return parser


async def _run(args) -> int:
    async with BrokerClient(args.url, ca_file=args.ca, cert_file=args.cert, key_file=args.key) as client:
        if args.command == "inventory":
            result = await client.inventory_find(
                args.grant, label=args.label, tags=args.tags,
                environment=args.environment, cursor=args.cursor, limit=args.limit,
            )
            sys.stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=True) + "\n")
            return 0
        query = [_pair(item) for item in args.query]
        headers = dict(_pair(item) for item in args.header)
        if len(headers) != len(args.header):
            raise BrokerClientError("request-invalid")
        body = _read_body(args.body_file)
        result = await client.request(
            args.grant, args.binding, args.method, args.path,
            query=query, headers=headers, body=body,
        )
        sys.stderr.write(f"upstream status: {result.get('status', 'unknown')}\n")
        sys.stdout.buffer.write(base64.b64decode(result["body_b64"], validate=True))
        sys.stdout.buffer.flush()
        return 0


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
        return asyncio.run(_run(args))
    except BrokerClientError as error:
        sys.stderr.write(f"leakguard-agent: {error.code}\n")
        return 2
    except (OSError, ValueError):
        sys.stderr.write("leakguard-agent: operation-failed\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("leakguard-agent: interrupted\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
