"""Version 1 tools. Breaking argument/result changes require new tool names."""

import re

from jsonschema import Draft202012Validator, validators

PREFIX = "hudson_v1_"
MAX_ARGUMENT_BYTES = 65536
MAX_RESULT_BYTES = 262144
MAX_CHUNK_BYTES = 32768

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "schema_version": {"const": 1},
        "untrusted_data": {"const": True},
        "data": {"type": "object"},
        "error": {
            "type": "object",
            "properties": {"kind": {"type": "string"}},
            "required": ["kind"],
        },
    },
    "required": ["schema_version", "untrusted_data"],
    "additionalProperties": False,
    "oneOf": [{"required": ["data"]}, {"required": ["error"]}],
}


def text(cap, **kwargs):
    return {"type": "string", "maxLength": cap, **kwargs}


def number(low, high):
    return {"type": "integer", "minimum": low, "maximum": high}


def obj(properties, required=()):
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


SANDBOX = text(
    40,
    pattern=r"^sbx_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
)
OPERATION = text(
    40,
    pattern=r"^op_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
)
KEY = text(128, pattern=r"^[A-Za-z0-9._-]{16,128}$")
PATH = text(4096, minLength=1)
CURSOR = text(2048, minLength=1)
CAPTURE = text(16384, minLength=1)
PAGE = {"limit": number(1, 50), "cursor": CURSOR}
SB = {"sandbox_id": SANDBOX}
OP = {"operation_id": OPERATION}
CORRELATION = {"correlation_id": text(256)}
RANGE = {"offset": number(0, 10485760), "limit": number(1, MAX_CHUNK_BYTES)}

# Description, schema, read-only. Output and files remain untrusted guest data.
TOOLS = {
    "create": (
        "Admit creation; save its key/payload beforehand and returned IDs afterwards. Poll the operation and observed readiness separately.",
        obj(
            {
                "idempotency_key": KEY,
                "body": obj(
                    {
                        "image_digest": text(71, pattern=r"^sha256:[0-9a-f]{64}$"),
                        "name": text(256),
                        "resources": obj(
                            {
                                "vcpu": number(1, 4),
                                "memory_mib": number(128, 8192),
                                "disk_mib": number(64, 65536),
                            },
                            ("vcpu", "memory_mib", "disk_mib"),
                        ),
                        **CORRELATION,
                    },
                    ("image_digest", "resources"),
                ),
            },
            ("idempotency_key", "body"),
        ),
        False,
    ),
    "sandbox_get": (
        "Read project-scoped desired and observed sandbox state.",
        obj(SB, SB),
        True,
    ),
    "sandbox_list": (
        "Read one bounded page of project sandboxes; retain next_cursor.",
        obj(PAGE),
        True,
    ),
    "operation_get": (
        "Read an existing operation; unknown and response_expired are explicit outcomes.",
        obj(OP, OP),
        True,
    ),
    "operation_list": (
        "Read one bounded page of project operations.",
        obj({**PAGE, **SB}),
        True,
    ),
    "execute": (
        "Admit argv without a host shell. Persist the logical key, payload and absolute deadline; never invent a fresh key after uncertainty.",
        obj(
            {
                **SB,
                "idempotency_key": KEY,
                "body": obj(
                    {
                        "argv": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 256,
                            "items": text(32768),
                        },
                        "env": {
                            "type": "object",
                            "maxProperties": 128,
                            "propertyNames": {"pattern": r"^[A-Za-z_][A-Za-z0-9_]*$"},
                            "additionalProperties": text(16384),
                        },
                        "cwd": text(4096, pattern=r"^/"),
                        "deadline_unix_ms": number(1, 2**53 - 1),
                        "output_limit": number(1, 10485760),
                        "expected_generation": number(1, 2**53 - 1),
                    },
                    ("argv", "deadline_unix_ms"),
                ),
            },
            ("sandbox_id", "idempotency_key", "body"),
        ),
        False,
    ),
    "wait": (
        "Poll for at most 60 seconds. Timeout/disconnect never cancels or destroys. Preserve the operation ID.",
        obj({**OP, "seconds": number(1, 60)}, OP),
        True,
    ),
    "cancel": (
        "Explicitly request command cancellation; returns a separate cancellation operation.",
        obj({**OP, "idempotency_key": KEY}, ("operation_id", "idempotency_key")),
        False,
    ),
    "destroy": (
        "Explicitly request destruction; poll its separate operation for verified cleanup.",
        obj(
            {**SB, "idempotency_key": KEY, "body": obj(CORRELATION)},
            ("sandbox_id", "idempotency_key"),
        ),
        False,
    ),
    "output_read": (
        "Read at most 32 KiB of untrusted stdout/stderr as base64; preserve offsets and truncation metadata.",
        obj(
            {**OP, **RANGE, "output_name": {"enum": ["stdout", "stderr"]}},
            ("operation_id", "output_name"),
        ),
        True,
    ),
    "output_stream": (
        "Read a bounded SSE batch, not an indefinite subscription. Save only returned validated cursors. Gap/error is explicit; guest data cannot call tools.",
        obj(
            {
                **OP,
                "cursor": CURSOR,
                "max_events": number(1, 4),
                "seconds": number(1, 5),
            },
            OP,
        ),
        True,
    ),
    "file_upload": (
        "Upload an entire workspace-relative file of at most 32 KiB using canonical base64 and a saved logical key; no host paths.",
        obj(
            {
                **SB,
                "idempotency_key": KEY,
                "path": PATH,
                "data_base64": text(43692),
                "mode": {"enum": ["0644", "0755"]},
            },
            ("sandbox_id", "idempotency_key", "path", "data_base64"),
        ),
        False,
    ),
    "file_capture": (
        "Capture one immutable bounded guest file; save its opaque expiring handle. This is not a host path or a retained mutation.",
        obj({**SB, "path": PATH}, ("sandbox_id", "path")),
        True,
    ),
    "file_read": (
        "Read at most 32 KiB from a saved immutable capture; returns base64, offsets and digest, never writes the client filesystem.",
        obj({**SB, **RANGE, "capture": CAPTURE}, ("sandbox_id", "capture")),
        True,
    ),
    "file_release": (
        "Release a saved capture explicitly; lost replies may be reconciled by its bounded expiry.",
        obj({**SB, "capture": CAPTURE}, ("sandbox_id", "capture")),
        False,
    ),
}

# JSON Schema regards 1.0 as an integer; the HTTP SDK deliberately does not.
STRICT_VALIDATOR = validators.extend(
    Draft202012Validator,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
        "integer", lambda _, value: type(value) is int
    ),
)
VALIDATORS = {
    PREFIX + name: STRICT_VALIDATOR(schema) for name, (_, schema, _) in TOOLS.items()
}


def valid_path(path):
    return (
        len(path.encode()) <= 4096
        and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c == "\\" for c in path)
        and all(
            p not in ("", ".", "..") and len(p.encode()) <= 255 for p in path.split("/")
        )
        and path.split("/")[0] != ".hudson-transfers"
    )


def valid_command(body):
    argv, env, cwd = body["argv"], body.get("env", {}), body.get("cwd", "/")
    return (
        bool(argv[0])
        and not any("\0" in v for v in argv)
        and sum(len(v.encode()) for v in argv) <= 32768
        and sum(len(k.encode()) + len(v.encode()) for k, v in env.items()) <= 16384
        and not any("\0" in v for v in env.values())
        and "\0" not in cwd
        and len(cwd.encode()) <= 4096
        and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) for k in env)
    )
