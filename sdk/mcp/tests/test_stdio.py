"""Official client -> subprocess stdio -> real SDK -> private local HTTPS."""

import asyncio
import datetime
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from mcp import Client, StdioServerParameters

from test_adapter import KEY, OP, SB, SECRET, admitted, config, operation
from hudson_sandbox_mcp.stdio import MAX_FRAME_BYTES


class HTTPSFixture:
    def __init__(self, root):
        self.requests = []
        self.mode = "ok"
        self.entered = threading.Event()
        self.unblock = threading.Event()
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Hudson isolated fixture")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        (root / "ca.pem").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )
        (root / "ca.pem").chmod(0o600)
        (root / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (root / "key.pem").chmod(0o600)
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                fixture.requests.append(
                    ("GET", self.path, self.headers["Authorization"], b"")
                )
                if fixture.mode == "blocked":
                    fixture.entered.set()
                    fixture.unblock.wait(5)
                if fixture.mode == "revoked":
                    self.reply(
                        401, {"status": 401, "code": "unauthorized", "title": SECRET}
                    )
                elif fixture.mode == "foreign":
                    self.reply(
                        404,
                        {
                            "status": 404,
                            "code": "not_found",
                            "title": "resource not in current project",
                        },
                    )
                elif self.path.startswith("/v1/operations/"):
                    self.reply(200, operation())
                else:
                    self.reply(200, {"items": [], "next_cursor": None})

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                fixture.requests.append(
                    ("POST", self.path, self.headers["Authorization"], body)
                )
                if fixture.mode == "lost":
                    # Mutation is recorded, then the authenticated reply is lost.
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                self.reply(202, admitted())

            def reply(self, status, value):
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "ca.pem", root / "key.pem")
        self.http.socket = tls.wrap_socket(self.http.socket, server_side=True)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.profile = config(
            root, "https://localhost:" + str(self.http.server_port), "ca.pem"
        )

    def close(self):
        self.unblock.set()
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.fixture = HTTPSFixture(Path(self.directory.name))
        self.params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "hudson_sandbox_mcp", "--config", str(self.fixture.profile)],
            env={
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

    async def asyncTearDown(self):
        await asyncio.to_thread(self.fixture.close)
        self.directory.cleanup()

    async def test_official_legacy_client_subprocess_https_and_reconnect(self):
        async with Client(self.params, mode="legacy") as client:
            self.assertEqual(client.protocol_version, "2025-11-25")
            self.assertEqual(len((await client.list_tools()).tools), 15)
            answer = await client.call_tool(
                "hudson_v1_execute",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "body": {"argv": ["true"], "deadline_unix_ms": 2000000000000},
                },
            )
            self.assertFalse(answer.is_error)
            self.assertEqual(answer.structured_content["data"]["operation_id"], OP)
        # Closing the MCP process sent no cleanup. Reconnect uses the saved ID.
        self.assertEqual([r[0] for r in self.fixture.requests], ["POST"])
        async with Client(self.params, mode="legacy") as client:
            answer = await client.call_tool(
                "hudson_v1_operation_get", {"operation_id": OP}
            )
            self.assertEqual(answer.structured_content["data"]["status"], "succeeded")
        self.assertEqual([r[0] for r in self.fixture.requests], ["POST", "GET"])
        self.assertTrue(all(r[2] == "Bearer " + SECRET for r in self.fixture.requests))

    async def test_lost_mutation_reply_and_revocation_in_real_transport(self):
        async with Client(self.params, mode="legacy") as client:
            self.fixture.mode = "lost"
            answer = await client.call_tool(
                "hudson_v1_destroy", {"sandbox_id": SB, "idempotency_key": KEY}
            )
            self.assertTrue(answer.is_error)
            self.assertEqual(
                answer.structured_content["error"]["mutation_outcome"], "uncertain"
            )
            self.assertEqual(len(self.fixture.requests), 1)
            self.fixture.mode = "revoked"
            denied = await client.call_tool(
                "hudson_v1_operation_get", {"operation_id": OP}
            )
            self.assertEqual(denied.structured_content["error"]["status"], 401)
            self.assertNotIn(SECRET, denied.content[0].text)
            self.fixture.mode = "foreign"
            foreign = await client.call_tool(
                "hudson_v1_operation_get", {"operation_id": OP}
            )
            self.assertTrue(foreign.is_error)
            self.assertEqual(foreign.structured_content["error"]["status"], 404)

    async def test_modern_sdk_client_uses_same_tools(self):
        async with Client(self.params) as client:
            answer = await client.call_tool("hudson_v1_sandbox_list", {})
            self.assertFalse(answer.is_error)
            self.assertEqual(answer.structured_content["data"]["items"], [])

    async def test_disconnecting_during_wait_sends_no_cleanup(self):
        self.fixture.mode = "blocked"
        async with Client(self.params, mode="legacy") as client:
            task = asyncio.create_task(
                client.call_tool("hudson_v1_wait", {"operation_id": OP, "seconds": 60})
            )
            self.assertTrue(await asyncio.to_thread(self.fixture.entered.wait, 3))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.fixture.unblock.set()
        self.assertTrue(self.fixture.requests)
        self.assertTrue(all(r[0] == "GET" for r in self.fixture.requests))

    async def test_bad_or_oversized_stdio_fails_closed_and_redacts_input(self):
        for data in (
            b'{"jsonrpc":"2.0","id":1,"id":2}\n',
            (SECRET.encode() * (MAX_FRAME_BYTES // len(SECRET) + 1)) + b"\n",
        ):

            def process():
                return subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "hudson_sandbox_mcp",
                        "--config",
                        str(self.fixture.profile),
                    ],
                    input=data,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                    check=False,
                )

            completed = await asyncio.to_thread(process)
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn(SECRET.encode(), completed.stdout + completed.stderr)
            self.assertEqual(self.fixture.requests, [])


if __name__ == "__main__":
    unittest.main()
