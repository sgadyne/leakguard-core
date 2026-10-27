"""Protected foreground shell for the broker's local Unix admin socket."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import math
from pathlib import Path
import re
import shlex
import stat
import sys
import warnings


_MAX_LINE = 131072
_ERROR_CODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_DEFAULT_SOCKET = "/run/leakguard-broker/admin.sock"


class AdminCLIError(Exception):
    def __init__(self, code: str):
        self.code = code if _ERROR_CODE.fullmatch(code) else "admin-operation-failed"
        super().__init__(self.code)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: invalid command line\n")


def _parser() -> _Parser:
    parser = _Parser(prog="leakguard-admin", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    shell = commands.add_parser("shell", help="open one protected local admin session")
    shell.add_argument("--socket", type=Path, default=Path(_DEFAULT_SOCKET),
                       help="protected broker admin Unix socket")
    return parser


def _check_socket(path: Path) -> None:
    try:
        info = path.lstat()
        parent = path.parent.lstat()
    except OSError:
        raise AdminCLIError("admin-socket-unavailable") from None
    if (not stat.S_ISSOCK(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or
            stat.S_IMODE(info.st_mode) != 0o600 or stat.S_IMODE(parent.st_mode) != 0o700 or
            info.st_uid != parent.st_uid):
        raise AdminCLIError("admin-socket-unprotected")


def _read_policy(path: str) -> dict:
    try:
        data = Path(path).read_bytes()
        if len(data) > 128 * 1024:
            raise ValueError
        value = json.loads(data)
    except (OSError, ValueError, UnicodeDecodeError):
        raise AdminCLIError("policy-file-invalid") from None
    if type(value) is not dict:
        raise AdminCLIError("policy-file-invalid")
    return value


def _expect_count(parts: list[str], count: int) -> None:
    if len(parts) != count:
        raise AdminCLIError("command-invalid")


def _command(parts: list[str]) -> tuple[dict, str]:
    """Map one shell command into a socket request and a safe display mode."""
    if not parts:
        return {}, "empty"
    if parts == ["help"]:
        return {}, "help"
    op = parts[0]
    if op == "status":
        _expect_count(parts, 1)
        return {"op": "status"}, "status"
    if op == "init":
        _expect_count(parts, 1)
        return {"op": "init"}, "secret-init"
    if op == "unlock":
        if len(parts) not in (1, 2):
            raise AdminCLIError("command-invalid")
        request = {"op": "unlock"}
        if len(parts) == 2:
            try:
                ttl = int(parts[1])
            except ValueError:
                raise AdminCLIError("command-invalid") from None
            if not 1 <= ttl <= 3600:
                raise AdminCLIError("command-invalid")
            request["ttl"] = ttl
        return request, "secret-unlock"
    if op == "lock":
        _expect_count(parts, 1)
        return {"op": "lock"}, "status"
    if op == "credential" and len(parts) >= 2:
        action = parts[1]
        if action == "get":
            _expect_count(parts, 3)
            return {"op": "credential.get", "entry_id": parts[2]}, "raw-secret"
        if action == "put":
            if len(parts) < 3:
                raise AdminCLIError("command-invalid")
            request = {"op": "credential.put", "title": parts[2]}
            index = 3
            while index < len(parts):
                flag = parts[index]
                if flag == "--username" and index + 1 < len(parts):
                    request["username"] = parts[index + 1]
                    index += 2
                elif flag == "--entry-id" and index + 1 < len(parts):
                    request["entry_id"] = parts[index + 1]
                    index += 2
                else:
                    raise AdminCLIError("command-invalid")
            return request, "secret-put"
    if op == "principal" and len(parts) >= 2:
        if parts[1] == "enroll":
            _expect_count(parts, 4)
            fingerprint = parts[2]
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                raise AdminCLIError("command-invalid")
            return {"op": "principal.enroll", "fingerprint": fingerprint,
                    "principal": parts[3]}, "done"
        if parts[1] == "revoke":
            _expect_count(parts, 3)
            return {"op": "principal.revoke", "fingerprint": parts[2]}, "done"
    if op == "grant" and len(parts) >= 2:
        if parts[1] == "create":
            _expect_count(parts, 6)
            try:
                ttl, max_requests = int(parts[3]), int(parts[4])
            except ValueError:
                raise AdminCLIError("command-invalid") from None
            bindings = parts[5].split(",")
            # Permit a final optional separator only as a syntax error; there
            # is exactly one binding-list token in this deliberately small CLI.
            if not 1 <= ttl <= 86400 or not 1 <= max_requests <= 100_000 or not all(bindings):
                raise AdminCLIError("command-invalid")
            return {"op": "grant.create", "principal": parts[2], "ttl": ttl,
                    "max_requests": max_requests, "bindings": bindings}, "grant"
        if parts[1] == "revoke":
            _expect_count(parts, 3)
            return {"op": "grant.revoke", "grant_id": parts[2]}, "done"
    if op == "policy" and len(parts) >= 2 and parts[1] == "replace":
        _expect_count(parts, 3)
        return {"op": "policy.replace", "policy": _read_policy(parts[2])}, "done"
    if op in ("quit", "exit"):
        _expect_count(parts, 1)
        return {"op": "quit"}, "quit"
    raise AdminCLIError("command-invalid")


def _prompt_secret(label: str) -> str:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise AdminCLIError("interactive-terminal-required")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(label)
    except getpass.GetPassWarning:
        raise AdminCLIError("secret-input-unavailable") from None
    except (EOFError, KeyboardInterrupt):
        raise AdminCLIError("secret-input-cancelled") from None
    except OSError:
        # A detached or broken controlling terminal must close the sole admin
        # connection, which causes the broker to lock and revoke its grants.
        raise AdminCLIError("terminal-lost") from None


def _with_secret(request: dict, mode: str) -> dict:
    if mode == "secret-init":
        first = _prompt_secret("New vault passphrase: ")
        second = _prompt_secret("Confirm vault passphrase: ")
        if first != second:
            raise AdminCLIError("passphrase-mismatch")
        request["passphrase"] = first
    elif mode == "secret-unlock":
        request["passphrase"] = _prompt_secret("Vault passphrase: ")
    elif mode == "secret-put":
        request["secret"] = _prompt_secret("Credential secret: ")
    return request


def _safe_json(value) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        return "{}"


def _safe_status(result) -> dict | None:
    if type(result) is not dict:
        return None
    unlocked = result.get("unlocked")
    deadline = result.get("deadline")
    version = result.get("policy_version")
    grants = result.get("grants")
    if type(unlocked) is not bool or (deadline is not None and
            (type(deadline) not in (int, float) or not math.isfinite(deadline))):
        return None
    if type(version) is not str or not re.fullmatch(r"[0-9a-f]{64}", version):
        return None
    if type(grants) is not int or grants < 0:
        return None
    return {"unlocked": unlocked, "deadline": deadline,
            "policy_version": version, "grants": grants}


def _display(mode: str, response: dict, out) -> None:
    if response.get("ok") is not True:
        code = response.get("error")
        safe_code = code if type(code) is str and _ERROR_CODE.fullmatch(code) else "admin-operation-failed"
        out.write(f"error: {safe_code}\n")
        return
    result = response.get("result")
    if mode == "raw-secret":
        if not out.isatty():
            out.write("error: reveal-requires-terminal\n")
            return
        if type(result) is not dict or type(result.get("secret")) is not str:
            out.write("error: response-invalid\n")
            return
        # This is the only command that writes a raw credential to stdout.
        out.write(result["secret"] + "\n")
        out.flush()
    elif mode in {"status", "secret-init", "secret-unlock"}:
        status = _safe_status(result)
        if status is None:
            out.write("error: response-invalid\n")
        else:
            out.write(_safe_json(status) + "\n")
    elif mode == "grant":
        if type(result) is dict:
            # Grant IDs and expiry are the complete result intended for this op.
            out.write(_safe_json({k: result[k] for k in ("grant_id", "expires_at") if k in result}) + "\n")
        else:
            out.write("done\n")
    elif mode == "secret-put":
        entry_id = result.get("id") if type(result) is dict else None
        if type(entry_id) is str and re.fullmatch(r"[0-9a-f]{32}", entry_id):
            out.write(f"credential entry id: {entry_id}\n")
        else:
            out.write("done\n")
    elif mode not in ("empty", "help", "quit"):
        out.write("done\n")


def _help(out) -> None:
    out.write(
        "Commands: status, init, unlock [seconds], lock,\n"
        "  credential put TITLE [--username USER] [--entry-id ID]\n"
        "  credential get ENTRY_ID  (explicit raw reveal to terminal)\n"
        "  principal enroll FINGERPRINT_SHA256_HEX PRINCIPAL\n"
        "  principal revoke FINGERPRINT_SHA256_HEX\n"
        "  grant create PRINCIPAL SECONDS MAX_REQUESTS BINDING[,BINDING...]\n"
        "  grant revoke GRANT_ID\n"
        "  policy replace JSON_FILE\n"
        "  quit\n"
        "Principal changes and policy replace are memory-only and are discarded\n"
        "on restart. Edit the daemon policy config for durable removal; restart\n"
        "revokes all grants, and a later unlock never restores old grants.\n"
    )


async def _exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    request: dict) -> dict:
    try:
        payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    except (TypeError, ValueError):
        raise AdminCLIError("admin-request-invalid") from None
    if len(payload) > _MAX_LINE:
        raise AdminCLIError("admin-request-too-large")
    try:
        writer.write(payload)
        await writer.drain()
        line = await reader.readline()
    except (OSError, asyncio.LimitOverrunError):
        raise AdminCLIError("admin-session-ended") from None
    if not line or not line.endswith(b"\n") or len(line) > _MAX_LINE:
        raise AdminCLIError("admin-session-ended")
    try:
        response = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdminCLIError("admin-response-invalid") from None
    if type(response) is not dict:
        raise AdminCLIError("admin-response-invalid")
    return response


async def _shell(socket_path: Path, *, input_fn=input, out=None) -> int:
    if out is None:
        out = sys.stdout
    _check_socket(socket_path)
    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path), limit=_MAX_LINE + 1)
    except (OSError, ValueError):
        raise AdminCLIError("admin-socket-unavailable") from None
    out.write("LeakGuard admin shell. Type help for commands.\n")
    try:
        while True:
            try:
                line = input_fn("leakguard-admin> ")
            except (EOFError, KeyboardInterrupt):
                # EOF and interruption deliberately close this sole session;
                # the server locks and revokes state on disconnect.
                return 0
            except OSError:
                return 0
            try:
                parts = shlex.split(line, posix=True)
                request, mode = _command(parts)
                if mode == "help":
                    _help(out)
                    continue
                if mode == "raw-secret" and not out.isatty():
                    out.write("error: reveal-requires-terminal\n")
                    continue
                request = _with_secret(request, mode)
                response = await _exchange(reader, writer, request)
                _display(mode, response, out)
                if mode == "quit":
                    return 0
            except AdminCLIError as error:
                out.write(f"error: {error.code}\n")
                if error.code in {
                    "secret-input-cancelled",
                    "secret-input-unavailable",
                    "terminal-lost",
                }:
                    # Abandon the owning admin session if secret entry cannot
                    # complete safely; disconnect locks and revokes its state.
                    return 0
                if error.code in {"admin-session-ended", "admin-response-invalid"}:
                    return 2
            except ValueError:
                out.write("error: command-invalid\n")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, RuntimeError):
            pass


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
        return asyncio.run(_shell(args.socket))
    except AdminCLIError as error:
        sys.stderr.write(f"leakguard-admin: {error.code}\n")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
