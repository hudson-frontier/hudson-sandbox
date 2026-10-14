#!/usr/bin/env python3
"""Verify every configured guest image before starting the existing Linux host."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile

import guest_image

CAP = 65536


class LaunchError(Exception):
    """Fixed operator diagnostic; no configuration/credential contents."""


def require(condition, message):
    if not condition:
        raise LaunchError(message)


def trusted_parents(path):
    require(
        path.is_absolute() and path.resolve() == path,
        "use canonical absolute operator paths",
    )
    for parent in path.parents:
        meta = parent.stat()
        require(
            meta.st_uid in (0, os.geteuid()), "operator path has an untrusted owner"
        )
        require(
            not meta.st_mode & 0o022
            or (meta.st_uid == 0 and meta.st_mode & stat.S_ISVTX),
            "operator path has a writable unprotected parent",
        )


def owned_file(path, private=False):
    trusted_parents(path)
    meta = path.lstat()
    require(
        stat.S_ISREG(meta.st_mode)
        and meta.st_uid == os.geteuid()
        and not meta.st_mode & (0o077 if private else 0o022),
        "use owned regular operator files with safe permissions",
    )


def private_json(path):
    owned_file(path, private=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        meta = os.fstat(source.fileno())
        require(
            stat.S_ISREG(meta.st_mode)
            and meta.st_uid == os.geteuid()
            and not meta.st_mode & 0o077
            and meta.st_size <= CAP,
            "invalid private operator metadata",
        )
        data = source.read(CAP + 1)
        require(len(data) <= CAP, "operator metadata exceeds 64 KiB")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate operator metadata field")
            result[key] = value
        return result

    value = json.loads(
        data,
        object_pairs_hook=unique,
        parse_constant=lambda _: require(False, "nonfinite operator metadata"),
    )
    require(isinstance(value, dict), "operator metadata must be an object")
    return data, value


def verified_images(config, policy, architecture):
    require(
        set(policy) == {"version", "images"}
        and type(policy["version"]) is int
        and policy["version"] == 1
        and isinstance(policy["images"], list)
        and 1 <= len(policy["images"]) <= 64,
        "invalid image verification policy",
    )
    configured = config.get("images")
    require(
        isinstance(configured, dict) and 1 <= len(configured) <= 64,
        "host requires an explicit image map",
    )
    verified = {}
    for entry in policy["images"]:
        require(
            isinstance(entry, dict)
            and set(entry) == {"directory", "manifest_sha256"}
            and isinstance(entry["directory"], str)
            and isinstance(entry["manifest_sha256"], str)
            and re.fullmatch("[0-9a-f]{64}", entry["manifest_sha256"]) is not None,
            "invalid image verification entry",
        )
        directory = Path(entry["directory"])
        trusted_parents(directory / "manifest.json")
        meta = directory.lstat()
        require(
            stat.S_ISDIR(meta.st_mode)
            and meta.st_uid == os.geteuid()
            and not meta.st_mode & 0o022,
            "image directory must be operator controlled",
        )
        for name in guest_image.ARTIFACTS | {"manifest.json"}:
            owned_file(directory / name)
        manifest = guest_image.verify(directory, entry["manifest_sha256"], architecture)
        digest = "sha256:" + manifest["artifacts"]["rootfs.ext4"]["sha256"]
        require(digest not in verified, "duplicate verified image")
        expected = {
            kind: {
                "path": str(directory / filename),
                "sha256": manifest["artifacts"][filename]["sha256"],
            }
            for kind, filename in (("kernel", "kernel.bin"), ("rootfs", "rootfs.ext4"))
        }
        require(
            configured.get(digest) == expected,
            "host image mapping differs from verified artifacts",
        )
        verified[digest] = manifest
    require(
        set(configured) == set(verified), "every host image needs a verified manifest"
    )
    capabilities = config.get("capabilities")
    if capabilities is not None:
        require(
            isinstance(capabilities, dict)
            and capabilities.get("architecture") == architecture
            and isinstance(capabilities.get("images"), list),
            "host capability image contract mismatch",
        )
        advertised = capabilities["images"]
        require(
            len(advertised) == len(verified), "host capability image contract mismatch"
        )
        seen = set()
        for image in advertised:
            require(isinstance(image, dict), "host capability image contract mismatch")
            digest = image.get("rootfs_digest")
            require(
                isinstance(digest, str) and digest in verified and digest not in seen,
                "host capability image contract mismatch",
            )
            seen.add(digest)
            manifest = verified[digest]
            require(
                image.get("kernel_digest")
                == "sha256:" + manifest["artifacts"]["kernel.bin"]["sha256"]
                and type(image.get("minimum_disk_mib")) is int
                and image["minimum_disk_mib"] >= manifest["minimum_disk_mib"]
                and image.get("guest_version") == manifest["guest_version"]
                and type(image.get("bootstrap_version")) is int
                and image["bootstrap_version"] == manifest["bootstrap_version"]
                and type(image.get("guest_protocol_version")) is int
                and image["guest_protocol_version"]
                == manifest["guest_protocol_version"]
                and capabilities.get("firecracker_version")
                == manifest["firecracker_version"],
                "host capability image contract mismatch",
            )
    return sorted(verified)


@contextmanager
def verified_snapshot(config_path, policy_path, architecture):
    # Verify and launch from the SAME bytes. A before/after reread would allow
    # an A -> B -> A source-config race to launch an unverified mapping.
    raw, config = private_json(config_path)
    _, policy = private_json(policy_path)
    images = verified_images(config, policy, architecture)
    temporary_parent = Path(tempfile.gettempdir()).resolve()
    trusted_parents(temporary_parent / "snapshot-parent-check")
    with tempfile.TemporaryDirectory(
        prefix="hudson-verified-host-", dir=temporary_parent
    ) as temporary:
        directory = Path(temporary)
        snapshot = directory / "host.json"
        fd = os.open(
            snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        yield snapshot, images


def run_host(binary, arguments):
    child = None
    handlers = {}
    pending = []

    def forward(number, _):
        if child is None:
            pending.append(number)
        elif child.poll() is None:
            child.send_signal(number)

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, forward)
        child = subprocess.Popen([str(binary), *arguments], stdin=subprocess.DEVNULL)
        for number in pending:
            forward(number, None)
        result = child.wait()
        return result if result >= 0 else 128 - result
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def run(args):
    require(
        os.name == "posix" and hasattr(os, "geteuid"),
        "verified host inputs require Unix operator permissions",
    )
    architecture = args.architecture or {"arm64": "aarch64", "amd64": "x86_64"}.get(
        platform.machine(), platform.machine()
    )
    require(architecture in guest_image.ARCHES, "unsupported image architecture")
    forwarded = args.host_arguments
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    require(
        not any(
            value == "--config" or value.startswith("--config=") for value in forwarded
        ),
        "host arguments cannot replace the verified configuration",
    )
    with verified_snapshot(args.config, args.image_policy, architecture) as (
        snapshot,
        images,
    ):
        if args.check_only:
            print(
                json.dumps(
                    {
                        "guest_images_verified": True,
                        "architecture": architecture,
                        "image_digests": images,
                    }
                )
            )
            return 0
        require(
            platform.system() == "Linux" and os.geteuid() == 0,
            "starting the real host requires the Linux operator account",
        )
        native = {"arm64": "aarch64", "amd64": "x86_64"}.get(
            platform.machine(), platform.machine()
        )
        require(native == architecture, "host and image architectures differ")
        require(
            args.host_binary is not None
            and isinstance(args.host_sha256, str)
            and re.fullmatch("[0-9a-f]{64}", args.host_sha256) is not None,
            "pin the existing host executable before launch",
        )
        owned_file(args.host_binary)
        require(
            args.host_binary.stat().st_mode & stat.S_IXUSR
            and guest_image.sha256(args.host_binary)[0] == args.host_sha256,
            "host executable integrity mismatch",
        )
        return run_host(args.host_binary, ["--config", str(snapshot), *forwarded])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--image-policy", required=True, type=Path)
    parser.add_argument("--architecture", choices=guest_image.ARCHES)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--host-binary", type=Path)
    parser.add_argument("--host-sha256")
    parser.add_argument("host_arguments", nargs=argparse.REMAINDER)
    try:
        return run(parser.parse_args())
    except (LaunchError, guest_image.ImageError) as error:
        print(str(error) + ".", file=sys.stderr)
    except KeyboardInterrupt:
        print(
            "Verified startup interrupted; retained allocations still require reconciliation.",
            file=sys.stderr,
        )
        return 130
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        print(
            "Verified host startup failed; inspect private inputs and retained allocation state.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
