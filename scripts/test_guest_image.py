"""Pure verifier regressions plus unprivileged ext4 assembly, never KVM."""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import guest_image as image


def elf_bytes(arch):
    head = bytearray(64)
    head[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", head, 18, image.ARCHES[arch])
    return bytes(head)


def config_bytes():
    return (
        "\n".join(
            k + "=" + v if v != "n" else "# " + k + " is not set"
            for k, v in image.REQUIRED.items()
        )
        + '\nCONFIG_LSM="lockdown"\n'
    ).encode()


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()

    def tearDown(self):
        self.directory.cleanup()

    def test_kernel_required_settings_and_modules_are_fail_closed(self):
        path = self.root / "config"
        path.write_bytes(config_bytes())
        image.kernel_config(path)
        for key, expected in image.REQUIRED.items():
            original = path.read_bytes()
            path.write_bytes(
                config_bytes().replace(
                    (key + "=" + expected).encode(), (key + "=n").encode()
                )
                if expected == "y"
                else config_bytes().replace(
                    ("# " + key + " is not set").encode(), (key + "=y").encode()
                )
            )
            with self.subTest(key=key), self.assertRaises(image.ImageError):
                image.kernel_config(path)
            path.write_bytes(original)
        for extra in (b"CONFIG_FAKE_DEVICE=m\n", b"CONFIG_MODULES=y\n"):
            path.write_bytes(config_bytes() + extra)
            with self.assertRaises(image.ImageError):
                image.kernel_config(path)

    def test_binaries_reject_wrong_architecture_or_truncation(self):
        path = self.root / "agent"
        for arch in image.ARCHES:
            path.write_bytes(elf_bytes(arch))
            image.elf(path, arch)
            other = "aarch64" if arch == "x86_64" else "x86_64"
            with self.assertRaises(image.ImageError):
                image.elf(path, other)
        path.write_bytes(b"#!/bin/sh\n")
        with self.assertRaises(image.ImageError):
            image.elf(path, "x86_64")

    def test_hash_rejects_symlink_empty_nonregular_and_byte_overflow(self):
        path = self.root / "file"
        for content, cap in ((b"", 10), (b"x" * 11, 10)):
            path.write_bytes(content)
            with self.assertRaises(image.ImageError):
                image.sha256(path, cap)
        if os.name == "posix":
            linked = self.root / "link"
            linked.symlink_to(path)
            with self.assertRaises(OSError):
                image.sha256(linked)
        path.write_bytes(b"verified")
        self.assertEqual(
            image.sha256(path), (hashlib.sha256(b"verified").hexdigest(), 8)
        )

    def test_metadata_duplicate_keys_oversize_and_manifest_pin(self):
        path = self.root / "manifest.json"
        path.write_bytes(b'{"version":1,"version":2}')
        with self.assertRaises(image.ImageError):
            image.read_json(path)
        path.write_bytes(b"x" * 65537)
        with self.assertRaises(image.ImageError):
            image.read_json(path)
        path.write_bytes(b'{"version":1}')
        with self.assertRaises(image.ImageError):
            image.verify(self.root, "a" * 64, "x86_64")

    def test_source_extractor_preserves_top_level_inputs_and_executable_scripts(self):
        archive = self.root / "source.tar"
        with tarfile.open(archive, "w") as tar:
            for name, content, mode in (
                ("Cargo.lock", b"locked", 0o644),
                ("kernel/build.sh", b"#!/bin/sh\n", 0o755),
            ):
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(content), mode
                tar.addfile(member, io.BytesIO(content))
        stage = self.root / "stage"
        stage.mkdir()
        image.extract_source(archive, stage)
        self.assertEqual((stage / "Cargo.lock").read_bytes(), b"locked")
        self.assertEqual((stage / "kernel/build.sh").read_bytes(), b"#!/bin/sh\n")
        if os.name == "posix":
            self.assertEqual((stage / "kernel/build.sh").stat().st_mode & 0o777, 0o755)

    def test_source_extractor_rejects_traversal_links_duplicates_and_byte_overflow(
        self,
    ):
        for names in (
            ("../outside",),
            ("/absolute",),
            ("source/../../outside",),
            ("same", "same"),
        ):
            archive = self.root / "bad.tar"
            with tarfile.open(archive, "w") as tar:
                for name in names:
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    tar.addfile(member, io.BytesIO(b"x"))
            with self.subTest(names=names), self.assertRaises(image.ImageError):
                image.extract_source(archive, self.root)
        archive = self.root / "link.tar"
        with tarfile.open(archive, "w") as tar:
            member = tarfile.TarInfo("source/link")
            member.type, member.linkname = tarfile.SYMTYPE, "../../outside"
            tar.addfile(member)
        for allowed in (False, True):
            with self.assertRaises(image.ImageError):
                image.extract_source(
                    archive, self.root, prefix="source", allow_links=allowed
                )
        archive = self.root / "large.tar"
        with tarfile.open(archive, "w") as tar:
            member = tarfile.TarInfo("large")
            member.size = 10
            tar.addfile(member, io.BytesIO(b"x" * 10))
        with self.assertRaises(image.ImageError):
            image.extract_source(archive, self.root, max_bytes=9)

    def test_missing_init_or_agent_fails_before_filesystem_assembly(self):
        output = self.root / "out"
        output.mkdir()
        for name, data in (
            ("sandbox-guest", elf_bytes("x86_64")),
            ("kernel.bin", elf_bytes("x86_64")),
            ("kernel.config", config_bytes()),
        ):
            (output / name).write_bytes(data)
        rootfs = self.root / "rootfs"
        rootfs.mkdir()
        for which in ("init", "usr/local/libexec/hudson/sandbox-guest"):
            path = rootfs / which
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(elf_bytes("x86_64"))
            path.chmod(0o755)
        for which in ("init", "usr/local/libexec/hudson/sandbox-guest"):
            path = rootfs / which
            original = path.read_bytes()
            path.write_bytes(b"tampered")
            with patch.object(image, "rootfs_image") as assemble:
                with self.assertRaises(image.ImageError):
                    image.assemble("x86_64", "a" * 40, rootfs, output)
                assemble.assert_not_called()
            path.write_bytes(original)


@unittest.skipUnless(
    os.name == "posix" and shutil.which("mke2fs") and shutil.which("debugfs"),
    "unprivileged ext4 tools required",
)
class FilesystemTests(unittest.TestCase):
    def test_verified_bundle_checks_actual_init_even_with_rewritten_file_hash(self):
        with tempfile.TemporaryDirectory(prefix="hudson-bundle-test-") as temporary:
            root = Path(temporary).resolve()
            output, tree = root / "out", root / "rootfs"
            output.mkdir()
            tree.mkdir()
            (tree / "etc").mkdir()
            for name in ("init", "usr/local/libexec/hudson/sandbox-guest"):
                path = tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(elf_bytes("x86_64"))
                path.chmod(0o755)
            for name, data in (
                ("sandbox-guest", elf_bytes("x86_64")),
                ("kernel.bin", elf_bytes("x86_64")),
                ("kernel.config", config_bytes()),
                ("Cargo.lock", b"pinned fixture"),
                ("linux-source.tar.xz", b"source fixture"),
            ):
                (output / name).write_bytes(data)
            pins = image.read_json(image.PINS_PATH)
            pins["kernel_sha256"] = hashlib.sha256(b"source fixture").hexdigest()
            pins_path = root / "pins.json"
            pins_path.write_text(json.dumps(pins))
            with patch.object(image, "PINS_PATH", pins_path):
                image.assemble("x86_64", "a" * 40, tree, output)
                expected = image.sha256(output / "manifest.json")[0]
                image.verify(output, expected, "x86_64")
                # The SAME exact pinned bundle must verify from a fresh CRLF
                # checkout; normalization never changes exported artifact bytes.
                checkout = root / "crlf-checkout"
                recipe = checkout / "dev/guest-image/hardening.config"
                recipe.parent.mkdir(parents=True)
                recipe.write_bytes(
                    image.recipe_bytes(
                        image.ROOT / "dev/guest-image/hardening.config"
                    ).replace(b"\n", b"\r\n")
                )
                with patch.object(image, "ROOT", checkout):
                    image.verify(output, expected, "x86_64")
                with self.assertRaises(image.ImageError):
                    image.verify(output, expected, "aarch64")
                kernel = output / "kernel.bin"
                kernel.write_bytes(elf_bytes("aarch64"))
                with self.assertRaises(image.ImageError):
                    image.verify(output, expected, "x86_64")
                kernel.write_bytes(elf_bytes("x86_64"))
                image.run(
                    "debugfs",
                    "-w",
                    "-R",
                    "rm /init",
                    str(output / "rootfs.ext4"),
                    capture_output=True,
                )
                manifest = image.read_json(output / "manifest.json")
                digest, size = image.sha256(output / "rootfs.ext4")
                manifest["artifacts"]["rootfs.ext4"] = {"sha256": digest, "size": size}
                (output / "manifest.json").write_text(json.dumps(manifest))
                changed = image.sha256(output / "manifest.json")[0]
                with self.assertRaises(image.ImageError):
                    image.verify(output, changed, "x86_64")

    def test_filesystem_is_deterministic_across_changed_source_ctimes(self):
        with tempfile.TemporaryDirectory(prefix="hudson-ext4-test-") as temporary:
            root = Path(temporary)
            hashes = []
            for number in range(2):
                tree = root / str(number)
                tree.mkdir()
                (tree / "init").write_bytes(elf_bytes("x86_64"))
                (tree / "init").chmod(0o755)
                (tree / "usr/bin").mkdir(parents=True)
                (tree / "usr/bin/file with spaces").write_bytes(b"same content")
                (tree / "link").symlink_to("usr/bin/file with spaces")
                image.rootfs_image(
                    tree, root / (str(number) + ".ext4"), 1790812800, "same-source"
                )
                hashes.append(image.sha256(root / (str(number) + ".ext4"))[0])
            self.assertEqual(hashes[0], hashes[1])


if __name__ == "__main__":
    unittest.main()
