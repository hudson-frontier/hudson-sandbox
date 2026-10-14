"""Versioned workflow's readiness, stdout/stderr, resume and file read contract."""

import base64
import hashlib
import json
import unittest

import httpx
import test_operation_recovery as fixture

CORPUS, SB, OP = fixture.CORPUS, fixture.SB, fixture.OP


class WorkflowReadTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixture.WorkflowTests.asyncSetUp
    asyncTearDown = fixture.WorkflowTests.asyncTearDown

    async def test_shared_readiness_binary_output_sse_resume_and_verified_download(
        self,
    ):
        stdout = base64.b64decode(CORPUS["stdout_base64"])
        stderr = base64.b64decode(CORPUS["stderr_base64"])
        self.assertEqual(len(stdout), CORPUS["download"]["size"])
        self.assertEqual(
            hashlib.sha256(stdout).hexdigest(), CORPUS["download"]["sha256"]
        )
        captured = "workflow-private-capture"
        ready = False

        def binary(data, prefix, **values):
            headers = {
                "cache-control": "no-store",
                "content-type": "application/octet-stream",
                **{
                    "x-" + prefix + "-" + k.replace("_", "-"): str(v).lower()
                    for k, v in values.items()
                },
            }
            return httpx.Response(200, headers=headers, stream=httpx.ByteStream(data))

        def handler(request):
            path = request.url.path
            if path == "/v1/sandboxes/" + SB:
                return fixture.reply(
                    200,
                    {
                        "sandbox_id": SB,
                        "desired_state": "running",
                        "observed_state": "running" if ready else "creating",
                        "observation_simulated": True,
                        "image_digest": CORPUS["requests"]["create"]["body"][
                            "image_digest"
                        ],
                        "resources": {},
                        "generation": 1,
                        "created_at": "2026-10-14T00:00:00Z",
                    },
                )
            if "/outputs/" in path:
                data = stdout if path.endswith("stdout") else stderr
                offset = int(request.url.params.get("offset", "0"))
                return binary(
                    data[offset:],
                    "output",
                    offset=offset,
                    next_offset=len(data),
                    size=len(data),
                    seen=len(data) + 1000,
                    truncated=True,
                    eof=True,
                    simulated=True,
                )
            if path.endswith("/stream"):
                if "cursor" in request.url.params:
                    self.assertEqual(
                        request.url.params["cursor"], CORPUS["stream"]["resume_cursor"]
                    )
                    frame = (
                        "event: gap\ndata: "
                        + json.dumps({"code": CORPUS["stream"]["gap_code"]})
                        + "\n\n"
                    )
                else:
                    frame = (
                        "id: "
                        + CORPUS["stream"]["resume_cursor"]
                        + "\nevent: output\ndata: "
                        + json.dumps(
                            {
                                "stream": "stdout",
                                "offset": 0,
                                "next_offset": len(stdout),
                                "data_base64": CORPUS["stdout_base64"],
                                "at_end": True,
                                "complete": True,
                                "seen": len(stdout) + 1000,
                                "stored": len(stdout),
                                "truncated": True,
                                "simulated": True,
                                "guest_reported": True,
                            }
                        )
                        + "\n\n"
                    )
                return httpx.Response(
                    200,
                    headers={
                        "cache-control": "no-store",
                        "content-type": "text/event-stream",
                    },
                    stream=httpx.ByteStream(frame.encode()),
                )
            if request.method == "POST" and path.endswith("/files/captures"):
                self.assertEqual(
                    json.loads(request.content)["path"], CORPUS["download"]["path"]
                )
                return fixture.reply(
                    201,
                    {
                        "capture": captured,
                        "size": len(stdout),
                        "sha256": CORPUS["download"]["sha256"],
                        "expires_unix_ms": 2000000000000,
                        "chunk_size": 32768,
                        "simulated": True,
                        "guest_reported": True,
                    },
                )
            if request.method == "GET" and path.endswith("/files/captures"):
                self.assertEqual(request.headers["x-file-capture"], captured)
                return binary(
                    stdout,
                    "file",
                    offset=0,
                    next_offset=len(stdout),
                    size=len(stdout),
                    sha256=CORPUS["download"]["sha256"],
                    eof=True,
                    simulated=True,
                    guest_reported=True,
                )
            if request.method == "DELETE" and path.endswith("/files/captures"):
                return httpx.Response(
                    204,
                    headers={"cache-control": "no-store"},
                    stream=httpx.ByteStream(b""),
                )
            self.fail("unexpected workflow read")

        self.handler = handler
        observed = await self.client.get_sandbox(sandbox_id=SB)
        self.assertEqual(
            observed.observed_state, CORPUS["readiness"]["not_ready_observed_state"]
        )
        ready = True
        observed = await self.client.get_sandbox(sandbox_id=SB)
        self.assertEqual(
            observed.observed_state, CORPUS["readiness"]["ready_observed_state"]
        )
        self.assertTrue(observed.observation_simulated)
        for name, expected in (("stdout", stdout), ("stderr", stderr)):
            chunk = await self.client.read_output(
                operation_id=OP, output_name=name, offset=1, limit=32768
            )
            self.assertEqual(chunk.data, expected[1:])
            self.assertTrue(chunk.truncated)
        async with await self.client.stream_output(operation_id=OP) as stream:
            first = await anext(stream)
            cursor = first.cursor
            self.assertEqual(base64.b64decode(first.data.data_base64), stdout)
        async with await self.client.stream_output(
            operation_id=OP, cursor=cursor
        ) as stream:
            gap = await anext(stream)
            self.assertEqual(gap.event, "gap")
            self.assertEqual(gap.data.code, "output_expired")
        destination = self.root / "verified-download.bin"
        downloaded = await self.client.download(
            sandbox_id=SB, path=CORPUS["download"]["path"], destination=destination
        )
        self.assertEqual(destination.read_bytes(), stdout)
        self.assertTrue(downloaded["release_confirmed"])
        self.assertTrue(downloaded["simulated"])
        self.assertFalse(
            any(
                r.url.path.endswith("/execute")
                or r.url.path.endswith("/cancel")
                or r.url.path.endswith("/destroy")
                for r in self.requests
            )
        )


if __name__ == "__main__":
    unittest.main()
