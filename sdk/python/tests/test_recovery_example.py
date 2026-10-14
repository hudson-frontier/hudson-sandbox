"""Real SDK request/response parsing against a no-network HTTPX fixture."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
from hudson_sandbox import Client, ClientError

SPEC = importlib.util.spec_from_file_location(
    "recover_execute", Path(__file__).parents[1] / "examples" / "recover_execute.py"
)
example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(example)
SANDBOX = "sbx_01996110-7c00-7000-8000-000000000001"
OPERATION = "op_01996110-7c00-7000-8000-000000000002"
BODY = {"argv": ["printf", "one-effect"], "deadline_unix_ms": 4102444800000}


class FixtureStream(httpx.AsyncByteStream):
    def __init__(self, body):
        self.data = json.dumps(body).encode()

    async def __aiter__(self):
        yield self.data[:17]
        yield self.data[17:]


def wire_response(status, body):
    return httpx.Response(
        status,
        stream=FixtureStream(body),
        headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
    )


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_private_atomic_no_clobber_and_exclusive_lock(self):
        with example.Journal(self.root) as journal:
            with self.assertRaises(BlockingIOError):
                example.Journal(self.root)
            example.prepare(journal, "binding", SANDBOX, BODY)
            original = journal.read("execute.json")
            self.assertEqual((self.root / "execute.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                example.prepare(journal, "binding", SANDBOX, BODY)
            self.assertEqual(journal.read("execute.json"), original)
            self.assertEqual([p.name for p in self.root.iterdir()], ["execute.json"])

    def test_unsafe_directory_and_file_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(example.StateError):
            example.Journal(self.root)
        self.root.chmod(0o700)
        with example.Journal(self.root) as journal:
            example.prepare(journal, "binding", SANDBOX, BODY)
            (self.root / "execute.json").chmod(0o644)
            with self.assertRaises(example.StateError):
                example.load(journal, "binding")

    def test_symlink_and_oversize_rejected(self):
        source = self.root / "source"
        source.write_bytes(b"x" * 65537)
        source.chmod(0o600)
        with self.assertRaises(example.StateError):
            example.private_read(source)
        (self.root / "link").symlink_to(source)
        with self.assertRaises(OSError):
            example.private_read(self.root / "link")

    def test_duplicate_json_and_invalid_body_rejected(self):
        with self.assertRaises(example.StateError):
            example.decode(b'{"version":1,"version":2}')
        with example.Journal(self.root) as journal:
            with self.assertRaises((TypeError, ClientError)):
                example.prepare(journal, "binding", SANDBOX, dict(BODY, injected=True))
            self.assertFalse((self.root / "execute.json").exists())

    def test_receipt_cannot_bind_to_changed_request(self):
        with example.Journal(self.root) as journal:
            example.prepare(journal, "binding", SANDBOX, BODY)
            _, digest, _ = example.load(journal, "binding")
            example.save_receipt(journal, digest, OPERATION)
            with self.assertRaises(example.StateError):
                example.receipt(journal, hashlib.sha256(b"changed").hexdigest())

    def test_publish_failure_does_not_submit_or_clobber_request(self):
        with example.Journal(self.root) as journal:
            with patch.object(example.os, "fsync", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    example.prepare(journal, "binding", SANDBOX, BODY)
            self.assertEqual(list(self.root.iterdir()), [])


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "client.json"
        self.credential = self.root / "credential.json"
        self.credential.write_text(
            json.dumps(
                {
                    "version": 1,
                    "project_id": "prj_fixture",
                    "name": "fixture",
                    "token": "fixture-token",
                    "created_at": 1,
                    "expires_at": 4102444800,
                }
            )
        )
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "endpoint": "https://sandbox.test",
                    "credential_file": "credential.json",
                }
            )
        )
        for path in (self.config, self.credential):
            path.chmod(0o600)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.fingerprint = example.binding(self.config)
        with example.Journal(self.state) as journal:
            example.prepare(journal, self.fingerprint, SANDBOX, BODY)
        self.calls = []

    async def client(self, handler):
        client = Client(self.config)
        await client._http.aclose()
        client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return client

    def response(self, http_status=202, **changes):
        body = {
            "sandbox_id": SANDBOX,
            "operation_id": OPERATION,
            "status": "queued",
            "status_url": "/v1/operations/" + OPERATION,
        }
        body.update(changes)
        return wire_response(http_status, body)

    def operation(self, status="unknown", **changes):
        body = {
            "operation_id": OPERATION,
            "sandbox_id": SANDBOX,
            "kind": "execute",
            "status": status,
            "created_at": "2026-10-02T00:00:00Z",
        }
        body.update(changes)
        return wire_response(200, body)

    async def test_lost_reply_restart_preserves_payload_key_and_deadline(self):
        def handler(request):
            self.calls.append(
                (request.method, request.headers["Idempotency-Key"], request.content)
            )
            if len(self.calls) == 1:
                raise httpx.ReadError("lost acknowledgement", request=request)
            return self.response()

        before = (self.state / "execute.json").read_bytes()
        async with await self.client(handler) as client:
            with (
                example.Journal(self.state) as journal,
                self.assertRaises(ClientError) as error,
            ):
                await example.recover(client, journal, self.fingerprint, "submit")
        self.assertEqual(error.exception.kind, "transport")
        self.assertFalse((self.state / "receipt.json").exists())
        self.assertEqual(len(self.calls), 1)  # No implicit retry inside a call.
        async with await self.client(handler) as client:
            with example.Journal(self.state) as journal:
                result = await example.recover(
                    client, journal, self.fingerprint, "submit"
                )
        self.assertEqual(self.calls[0], self.calls[1])
        self.assertEqual(
            json.loads(self.calls[1][2])["deadline_unix_ms"], BODY["deadline_unix_ms"]
        )
        self.assertEqual((self.state / "execute.json").read_bytes(), before)
        self.assertEqual(result["operation_id"], OPERATION)

    async def test_post_link_fsync_failure_requires_durability_before_admission(self):
        (self.state / "execute.json").unlink()
        fsync = os.fsync

        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory sync failed")
            return fsync(fd)

        with example.Journal(self.state) as journal:
            with (
                patch.object(example.os, "fsync", side_effect=fail_directory),
                self.assertRaises(OSError),
            ):
                example.prepare(journal, self.fingerprint, SANDBOX, BODY)
        original = (self.state / "execute.json").read_bytes()

        def handler(request):
            self.calls.append(request.method)
            return self.response()

        async with await self.client(handler) as client:
            with example.Journal(self.state) as journal:
                with (
                    patch.object(example.os, "fsync", side_effect=fail_directory),
                    self.assertRaises(OSError),
                ):
                    await example.recover(client, journal, self.fingerprint, "submit")
        self.assertEqual(self.calls, [])
        self.assertEqual((self.state / "execute.json").read_bytes(), original)
        async with await self.client(handler) as client:
            with example.Journal(self.state) as journal:
                await example.recover(client, journal, self.fingerprint, "submit")
        self.assertEqual(self.calls, ["POST"])
        self.assertEqual((self.state / "execute.json").read_bytes(), original)

    async def test_saved_handle_only_polls_even_when_unknown_or_output_expired(self):
        with example.Journal(self.state) as journal:
            _, digest, _ = example.load(journal, self.fingerprint)
            example.save_receipt(journal, digest, OPERATION)

        def handler(request):
            self.calls.append(request.method)
            self.assertEqual(request.url.path, "/v1/operations/" + OPERATION)
            return self.operation(
                output_status="expired",
                result={"secret": "do-not-print"},
            )

        async with await self.client(handler) as client:
            for action in ("submit", "poll"):
                with example.Journal(self.state) as journal:
                    result = await example.recover(
                        client, journal, self.fingerprint, action
                    )
                self.assertEqual(result["status"], "unknown")
                self.assertFalse(result["response_expired"])
                self.assertEqual(result["output_status"], "expired")
                self.assertNotIn("do-not-print", json.dumps(result))
        self.assertEqual(self.calls, ["GET", "GET"])

    async def test_get_response_expiry_reports_error_without_resubmission(self):
        with example.Journal(self.state) as journal:
            _, digest, _ = example.load(journal, self.fingerprint)
            example.save_receipt(journal, digest, OPERATION)
        original = (self.state / "receipt.json").read_bytes()

        def handler(request):
            self.assertEqual(request.method, "GET")
            return wire_response(
                410,
                {
                    "title": "expired",
                    "status": 410,
                    "code": "response_expired",
                    "operation_id": OPERATION,
                },
            )

        async with await self.client(handler) as client:
            with (
                example.Journal(self.state) as journal,
                self.assertRaises(ClientError) as error,
            ):
                await example.recover(client, journal, self.fingerprint, "submit")
        self.assertEqual(error.exception.code, "response_expired")
        self.assertEqual(error.exception.operation_id, OPERATION)
        self.assertEqual((self.state / "receipt.json").read_bytes(), original)

    async def test_poll_without_receipt_never_mutates(self):
        def handler(request):
            self.fail("poll must not send anything without a handle")

        async with await self.client(handler) as client:
            with (
                example.Journal(self.state) as journal,
                self.assertRaises(example.StateError),
            ):
                await example.recover(client, journal, self.fingerprint, "poll")

    async def test_expired_admission_retains_authorized_handle(self):
        def handler(request):
            return wire_response(
                410,
                {
                    "title": "expired",
                    "status": 410,
                    "code": "response_expired",
                    "operation_id": OPERATION,
                },
            )

        async with await self.client(handler) as client:
            with example.Journal(self.state) as journal, self.assertRaises(ClientError):
                await example.recover(client, journal, self.fingerprint, "submit")
        with example.Journal(self.state) as journal:
            _, digest, _ = example.load(journal, self.fingerprint)
            self.assertEqual(example.receipt(journal, digest), OPERATION)

    async def test_conflict_or_revocation_does_not_create_receipt(self):
        for status, code in [(409, "conflict"), (401, "unauthenticated")]:

            def handler(request):
                return wire_response(
                    status,
                    {
                        "title": "backend-secret",
                        "status": status,
                        "code": code,
                        "operation_id": OPERATION,
                    },
                )

            async with await self.client(handler) as client:
                with (
                    example.Journal(self.state) as journal,
                    self.assertRaises(ClientError),
                ):
                    await example.recover(client, journal, self.fingerprint, "submit")
            self.assertFalse((self.state / "receipt.json").exists())

    async def test_changed_credential_binding_fails_before_network(self):
        self.credential.write_text(
            self.credential.read_text().replace("fixture-token", "rotated-token")
        )
        changed = example.binding(self.config)
        self.assertNotEqual(changed, self.fingerprint)
        async with await self.client(
            lambda _: self.fail("identity change must not send")
        ) as client:
            with (
                example.Journal(self.state) as journal,
                self.assertRaises(example.StateError),
            ):
                await example.recover(client, journal, changed, "submit")

    async def test_startup_profile_aba_cannot_change_the_submitted_origin_or_token(
        self,
    ):
        for changed_file in (self.config, self.credential):
            with self.subTest(file=changed_file.name):
                (self.state / "receipt.json").unlink(missing_ok=True)
                original = changed_file.read_bytes()
                replacements = {
                    self.config: original.replace(b"sandbox.test", b"other.test"),
                    self.credential: original.replace(b"fixture-token", b"other-token"),
                }
                unused_http = []
                loaded_paths = []

                def handler(request):
                    self.calls.append(request)
                    return self.response()

                def load_client(config_path):
                    # A -> B -> A defeats a before/after fingerprint check if
                    # the SDK independently reads the mutable source profile.
                    changed_file.write_bytes(replacements[changed_file])
                    try:
                        client = Client(config_path)
                    finally:
                        changed_file.write_bytes(original)
                    unused_http.append(client._http)
                    client._http = httpx.AsyncClient(
                        transport=httpx.MockTransport(handler)
                    )
                    loaded_paths.append(Path(config_path))
                    return client

                args = SimpleNamespace(
                    state=self.state, config=self.config, action="submit"
                )
                try:
                    with patch.object(example, "Client", side_effect=load_client):
                        result = await example.run(args)
                finally:
                    for transport in unused_http:
                        await transport.aclose()
                self.assertEqual(result["operation_id"], OPERATION)
                self.assertEqual(self.calls[-1].url.host, "sandbox.test")
                self.assertEqual(
                    self.calls[-1].headers["Authorization"], "Bearer fixture-token"
                )
                self.assertEqual(changed_file.read_bytes(), original)
                self.assertFalse(loaded_paths[-1].exists())

    async def test_startup_profile_change_stays_changed_and_sends_no_mutation(self):
        original = self.config.read_bytes()
        unused_http = []

        def load_client(config_path):
            client = Client(config_path)
            unused_http.append(client._http)
            client._http = httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda _: self.fail("changed profile must not send")
                )
            )
            self.config.write_bytes(original.replace(b"sandbox.test", b"other.test"))
            return client

        try:
            with (
                patch.object(example, "Client", side_effect=load_client),
                self.assertRaises(example.StateError),
            ):
                await example.run(
                    SimpleNamespace(
                        state=self.state, config=self.config, action="submit"
                    )
                )
        finally:
            self.config.write_bytes(original)
            for transport in unused_http:
                await transport.aclose()
        self.assertFalse((self.state / "receipt.json").exists())

    async def test_private_snapshot_is_removed_when_client_loading_fails(self):
        loaded = []

        def reject(config_path):
            config_path = Path(config_path)
            loaded.append(config_path)
            self.assertEqual(config_path.parent.stat().st_mode & 0o777, 0o700)
            for path in config_path.parent.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            raise ClientError("configuration")

        with (
            patch.object(example, "Client", side_effect=reject),
            self.assertRaises(ClientError),
        ):
            await example.run(
                SimpleNamespace(state=self.state, config=self.config, action="submit")
            )
        self.assertEqual(len(loaded), 1)
        self.assertFalse(loaded[0].parent.exists())
        self.assertTrue(self.config.exists())
        self.assertTrue(self.credential.exists())
        self.assertFalse((self.state / "receipt.json").exists())

    async def test_admitted_wrong_sandbox_or_invalid_id_rejected(self):
        for changes in [
            {"sandbox_id": SANDBOX[:-1] + "9"},
            {"operation_id": "invalid"},
            {"status": "backend-secret"},
        ]:
            async with await self.client(lambda _: self.response(**changes)) as client:
                with (
                    example.Journal(self.state) as journal,
                    self.assertRaises(example.StateError),
                ):
                    await example.recover(client, journal, self.fingerprint, "submit")
            self.assertFalse((self.state / "receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
