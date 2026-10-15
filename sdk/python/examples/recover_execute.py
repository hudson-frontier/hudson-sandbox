"""One-command recovery example; existing HTTPS SDK, no implicit mutation retry."""

import argparse
import asyncio
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

from hudsonbox import Client, ClientError, models, new_idempotency_key

CAP = 65536
ID = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
STATUSES = {"queued", "running", "succeeded", "failed", "cancelled", "unknown"}


class StateError(Exception):
    """Safe fixed message: never include payloads, tokens or backend output."""


def encode(value):
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(data) > CAP:
        raise StateError("state exceeds the example's 64 KiB bound")
    return data


def decode(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise StateError("duplicate state fields")
            value[key] = item
        return value

    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: invalid())


def invalid():
    raise StateError("invalid recovery state")


def private_read(path, directory=None, sync=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as source:
        meta = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != os.geteuid()
            or meta.st_mode & 0o077
            or meta.st_size > CAP
        ):
            raise StateError("use private, owned, regular files of at most 64 KiB")
        data = source.read(CAP + 1)
        if len(data) > CAP:
            invalid()
        if sync:
            os.fsync(source.fileno())
        return data


def profile_parts(config):
    """Read the exact private bytes that must identify the loaded client."""
    raw = private_read(config)
    cfg = decode(raw)
    parts = [raw, private_read(Path(config).parent / cfg["credential_file"])]
    if cfg.get("ca_file") is not None:
        parts.append(private_read(Path(config).parent / cfg["ca_file"]))
    return cfg, parts


def fingerprint(parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def binding(config):
    """Conservative identity binding: any config/credential/CA change fails closed."""
    return fingerprint(profile_parts(config)[1])


@contextmanager
def bound_profile(config):
    # A before/after reread cannot prove what the SDK loaded when the source
    # changes A -> B -> A. Load it only from a private snapshot of the exact
    # bytes used in the fingerprint. Keep the persisted fingerprint format.
    cfg, parts = profile_parts(config)
    with tempfile.TemporaryDirectory(prefix="hudson-recovery-profile-") as root:
        root = Path(root)

        def write(name, data):
            fd = os.open(
                root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "wb") as target:
                target.write(data)

        copied = dict(cfg)
        copied["credential_file"] = "credential.json"
        write("credential.json", parts[1])
        if cfg.get("ca_file") is not None:
            copied["ca_file"] = "ca.pem"
            write("ca.pem", parts[2])
        write("client.json", encode(copied))
        yield fingerprint(parts), root / "client.json"


class Journal:
    """Two immutable private records, exclusively locked through one directory fd."""

    def __init__(self, path, *, directory=None):
        self.fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
        )
        try:
            meta = os.fstat(self.fd)
            if meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
                raise StateError("use a private owned state directory (mode 0700)")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def read(self, name):
        return private_read(name, self.fd)

    def confirm_request(self, digest):
        # A previous writer may have died after link but before directory fsync.
        # Visibility alone must not allow admission to outrun the durable key.
        data = private_read("execute.json", self.fd, sync=True)
        if hashlib.sha256(data).hexdigest() != digest:
            invalid()
        os.fsync(self.fd)

    def write_new(self, name, data):
        scratch = ".staging-" + uuid.uuid4().hex
        fd = os.open(
            scratch,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            # Atomic publication, never overwrite a request/receipt from other work.
            os.link(
                scratch,
                name,
                src_dir_fd=self.fd,
                dst_dir_fd=self.fd,
                follow_symlinks=False,
            )
            os.fsync(self.fd)
        finally:
            os.unlink(scratch, dir_fd=self.fd)


def prepare(journal, fingerprint, sandbox_id, body):
    if not re.fullmatch("sbx_" + ID, sandbox_id):
        invalid()
    body = models.CommandInput(**body).to_wire()
    saved = {
        "version": 1,
        "client_binding": fingerprint,
        "sandbox_id": sandbox_id,
        "idempotency_key": new_idempotency_key(),
        "body": body,
    }
    journal.write_new("execute.json", encode(saved))


def load(journal, fingerprint):
    raw = journal.read("execute.json")
    saved = decode(raw)
    if (
        set(saved)
        != {"version", "client_binding", "sandbox_id", "idempotency_key", "body"}
        or type(saved["version"]) is not int
        or saved["version"] != 1
    ):
        invalid()
    if saved["client_binding"] != fingerprint:
        raise StateError("client identity changed; do not resubmit this saved mutation")
    if not isinstance(saved["sandbox_id"], str) or not re.fullmatch(
        "sbx_" + ID, saved["sandbox_id"]
    ):
        invalid()
    if not isinstance(saved["idempotency_key"], str) or not re.fullmatch(
        r"[A-Za-z0-9._-]{16,128}", saved["idempotency_key"]
    ):
        invalid()
    body = models.CommandInput(**saved["body"])
    if body.to_wire() != saved["body"]:
        invalid()
    return saved, hashlib.sha256(raw).hexdigest(), body


def receipt(journal, digest):
    try:
        value = decode(journal.read("receipt.json"))
    except FileNotFoundError:
        return None
    if (
        set(value) != {"version", "request_sha256", "operation_id"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["request_sha256"] != digest
    ):
        invalid()
    if not isinstance(value["operation_id"], str) or not re.fullmatch(
        "op_" + ID, value["operation_id"]
    ):
        invalid()
    return value["operation_id"]


def save_receipt(journal, digest, operation_id):
    if not isinstance(operation_id, str) or not re.fullmatch("op_" + ID, operation_id):
        invalid()
    journal.write_new(
        "receipt.json",
        encode({"version": 1, "request_sha256": digest, "operation_id": operation_id}),
    )


async def recover(client, journal, fingerprint, action):
    saved, digest, body = load(journal, fingerprint)
    handle = receipt(journal, digest)
    if handle is None:
        if action != "submit":
            raise StateError(
                "no saved handle; explicitly submit the unchanged request to reconcile admission"
            )
        journal.confirm_request(digest)
        # One explicit attempt; a lost reply leaves execute.json and its key intact.
        try:
            admitted = await client.execute_command(
                sandbox_id=saved["sandbox_id"],
                idempotency_key=saved["idempotency_key"],
                body=body,
            )
        except ClientError as error:
            if (
                error.kind == "http"
                and error.status == 410
                and error.code == "response_expired"
                and error.operation_id
            ):
                save_receipt(journal, digest, error.operation_id)
            raise
        if (
            admitted.sandbox_id != saved["sandbox_id"]
            or admitted.status not in STATUSES
        ):
            invalid()
        save_receipt(journal, digest, admitted.operation_id)
        return {
            "operation_id": admitted.operation_id,
            "status": admitted.status,
            "admission_only": True,
        }
    operation = await client.get_operation(operation_id=handle)
    if (
        operation.operation_id != handle
        or operation.sandbox_id != saved["sandbox_id"]
        or operation.kind != "execute"
        or operation.status not in STATUSES
        or operation.output_status
        not in (None, "none", "pending", "uploading", "published", "expired")
    ):
        invalid()
    # Do not print arbitrary workload result/error contents or turn unknown into retry.
    return {
        "operation_id": handle,
        "status": operation.status,
        "response_expired": operation.response_expired,
        "output_status": operation.output_status,
        "admission_only": False,
    }


async def run(args):
    with (
        Journal(args.state) as journal,
        bound_profile(args.config) as (profile_binding, config_path),
    ):
        async with Client(
            config_path
        ) as client:  # Existing private config and verified TLS.
            if binding(args.config) != profile_binding:
                raise StateError("client configuration changed during initialization")
            if args.action == "prepare":
                prepare(
                    journal,
                    profile_binding,
                    args.sandbox,
                    decode(private_read(args.request)),
                )
                return {"prepared": True, "submitted": False}
            return await recover(client, journal, profile_binding, args.action)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare_args = commands.add_parser(
        "prepare", help="Save a new immutable request; no API call"
    )
    prepare_args.add_argument("--sandbox", required=True)
    prepare_args.add_argument("--request", required=True, type=Path)
    commands.add_parser(
        "submit", help="One exact admission attempt; saved handles use GET only"
    )
    commands.add_parser(
        "poll", help="GET the saved handle; never submits, cancels or destroys"
    )
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args))))
        return 0
    except ClientError as error:
        print(
            json.dumps(
                {
                    "error": error.kind,
                    "status": error.status,
                    "code": error.code,
                    "operation_id": error.operation_id,
                }
            ),
            file=sys.stderr,
        )
    except StateError as error:
        print(str(error), file=sys.stderr)
    except KeyboardInterrupt:
        print(
            "client interrupted; retain the original request/key and saved handle",
            file=sys.stderr,
        )
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(
            "local recovery state invalid or unavailable; retain the original request and key",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
