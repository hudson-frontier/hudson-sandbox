"""Trusted operator entry point. Arguments contain a configuration path only."""

import argparse
import asyncio
import logging
import sys

from hudson_sandbox import Client

from .adapter import Adapter, server
from .stdio import run


async def serve(config):
    async with Client.from_config(config) as client:
        await run(server(Adapter(client)))


def main():
    parser = argparse.ArgumentParser(
        description="Optional project-authenticated local MCP stdio adapter"
    )
    parser.add_argument(
        "--config", required=True, help="Trusted private SDK configuration file"
    )
    args = parser.parse_args()
    # SDK validation/errors or HTTP logs can contain untrusted peer data. Protocol
    # results carry bounded sanitized diagnostics; no config/arguments are logged.
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(serve(args.config))
    except KeyboardInterrupt:
        return
    except Exception:
        print(
            "Hudson MCP adapter stopped: invalid configuration, frame or transport. Retain mutation keys and known operation IDs; cleanup remains explicit.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
