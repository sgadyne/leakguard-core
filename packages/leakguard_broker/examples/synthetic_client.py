"""Exercise the broker against the installed synthetic acceptance fixture."""
from __future__ import annotations

import argparse
import asyncio

from leakguard_broker.client import BrokerClient


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--grant", required=True)
    return parser


async def _run(args) -> None:
    async with BrokerClient(args.url, ca_file=args.ca,
                            cert_file=args.cert, key_file=args.key) as client:
        page = await client.inventory_find(args.grant, label="Synthetic test service", limit=20)
        for item in page["items"]:
            print(f"{item['id']}\t{item['label']}\t{item['environment']}")
        response = await client.request(
            args.grant, "synthetic-binding", "GET", "/fixture-health",
            query=[("format", "json")],
        )
        print(f"synthetic upstream status: {response['status']}")
        print(f"synthetic response body (base64): {response['body_b64']}")


if __name__ == "__main__":
    asyncio.run(_run(_parser().parse_args()))
