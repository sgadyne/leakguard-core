"""Foreground broker. Passwords are accepted only on its protected admin socket."""
import argparse
import asyncio
from pathlib import Path
import signal
import sys

from .errors import BrokerError
from .server import Broker, decode_json, server_tls


async def serve(config):
    required = {"policy", "vault_path", "admin_socket", "server_cert", "server_key", "client_ca"}
    if not required <= set(config) or set(config) - required - {"listen_host", "listen_port"}:
        raise BrokerError("config-invalid", 400)
    broker = Broker(config["policy"], Path(config["vault_path"]))
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    try:
        await broker.start(Path(config["admin_socket"]), config.get("listen_host", "127.0.0.1"),
                           config.get("listen_port", 8443),
                           server_tls(config["server_cert"], config["server_key"], config["client_ca"]))
        print("broker-ready", flush=True)
        await stopped.wait()
    finally:
        await broker.close()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main(argv=None):
    parser = argparse.ArgumentParser(description="LeakGuard scoped credential broker")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        with Path(args.config).open("rb") as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise BrokerError("config-invalid", 400)
        asyncio.run(serve(decode_json(raw)))
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("broker-start-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
