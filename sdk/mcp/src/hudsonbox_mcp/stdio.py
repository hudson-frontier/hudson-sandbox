"""Bound the official SDK stdio transport before it parses/allocates a frame."""

import json
import os
import sys
from contextlib import contextmanager

import anyio
from hudsonbox._wire import ClientError, parse_json
from mcp.server.stdio import stdio_server

MAX_FRAME_BYTES = 131072
MAX_RESPONSE_BYTES = 1048576
MAX_PENDING_REQUESTS = 8


class FrameError(Exception):
    def __init__(self):
        super().__init__("Invalid or oversized MCP frame; connection closed.")


class Frames:
    def __init__(self):
        self.pending = set()

    def receive(self, line):
        if len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
            raise FrameError()
        try:
            value = parse_json(line)
            if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
                raise FrameError()
            if "id" in value:
                key = value["id"]
                if (
                    type(key) not in (str, int)
                    or (isinstance(key, str) and len(key.encode()) > 128)
                    or (type(key) is int and abs(key) > 2**53 - 1)
                    or key in self.pending
                    or len(self.pending) >= MAX_PENDING_REQUESTS
                ):
                    raise FrameError()
                self.pending.add(key)
            return line.decode("utf-8")
        except (ClientError, UnicodeError, RecursionError, TypeError):
            raise FrameError() from None

    def sending(self, line):
        data = line.encode("utf-8")
        if len(data) > MAX_RESPONSE_BYTES:
            raise FrameError()
        value = json.loads(data)
        self.pending.discard(value.get("id"))
        return data


class Input:
    def __init__(self, file, frames):
        self.file, self.frames = file, frames

    def __aiter__(self):
        return self

    async def __anext__(self):
        line = await anyio.to_thread.run_sync(
            self.file.readline, MAX_FRAME_BYTES + 1, abandon_on_cancel=True
        )
        if not line:
            raise StopAsyncIteration
        return self.frames.receive(line)


class Output:
    def __init__(self, file, frames):
        self.file, self.frames = file, frames

    async def write(self, line):
        await anyio.to_thread.run_sync(self.file.write, self.frames.sending(line))

    async def flush(self):
        await anyio.to_thread.run_sync(self.file.flush)


@contextmanager
def private_stdio():
    """The SDK configuration supports Unix. Keep stray print/child output off fd 1."""
    sys.stdout.flush()
    incoming, outgoing = os.dup(0), os.dup(1)
    try:
        with open(os.devnull, "rb") as empty:
            os.dup2(empty.fileno(), 0)
        os.dup2(2, 1)
        # Duplicates are non-inheritable; children cannot reach the wire.
        with os.fdopen(incoming, "rb") as reader, os.fdopen(outgoing, "wb") as writer:
            incoming = outgoing = None
            frames = Frames()
            yield Input(reader, frames), Output(writer, frames)
    finally:
        # This context owns process stdio until exit; never expose it to a child.
        if incoming is not None:
            os.close(incoming)
        if outgoing is not None:
            os.close(outgoing)


async def run(server):
    with private_stdio() as (incoming, outgoing):
        async with stdio_server(stdin=incoming, stdout=outgoing) as (read, write):
            await server.run(read, write, server.create_initialization_options())
