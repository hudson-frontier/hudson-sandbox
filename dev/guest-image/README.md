# Pinned local guest image build

This recipe builds our init/agent, Linux kernel and Debian slim ext4 filesystem for [issue #108](https://github.com/hudson-infinity/hudson-sandbox/issues/108). Inputs are pinned in [pins.json](pins.json); the build combines an architecture-specific Firecracker config with [our required settings](hardening.config). Authenticated API boot, native aarch64 build/execution and supported-host isolation/teardown qualification remain pending.

On a native Linux builder with Git, Docker, Python and unprivileged `e2fsprogs` tools:

```sh
python3 scripts/build_guest_image.py --architecture x86_64 --destination /absolute/new/guest-image
python3 scripts/build_guest_image.py --architecture aarch64 --destination /absolute/new/guest-image-arm
```

Run only the command matching the builder architecture. WSL can build x86_64 artifacts without KVM; it does not qualify execution. The script packages committed guest source at `HEAD`; commit Rust/protocol changes before building. The working recipe is copied explicitly and its complete context digest is recorded. Docker receives a narrow Git archive of Cargo manifests/lock, Rust source and protobuf files. User configuration, `.git`, `.worktrees`, TLS credentials, host artifacts and local caches are excluded.

The destination must be a new canonical absolute directory. Failed output is retained; retry with a new directory. The final scratch image is exported through an invocation-owned container that is never started and is removed by exact ID. Existing containers, volumes and database/storage data are preserved. Build images/cache remain available for reuse; nothing is pushed to a registry.

## Sources and reproducibility

| Input | Selection |
| --- | --- |
| Rust/compiler base | Official Rust 1.92.0 bookworm, immutable multi-architecture OCI digest |
| Userland | Official Debian bookworm-slim, immutable multi-architecture OCI digest |
| Extra build tools | Signed Debian snapshot `20261001T000000Z`, with package/signature verification |
| Kernel | Kernel.org Linux 6.1.186 tar.xz, SHA-256 from [published sums](https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc) |
| Base kernel configs | Firecracker v1.17.0 immutable revision and per-architecture file digest |
| Guest/init | Committed repository revision, Rust 1.92.0 and locked Cargo crate checksums |
| Filesystem | Fixed 256 MiB ext4, UUID/hash seed, source epoch and inode timestamps |

The recipe disables modules and kexec, forces early confidentiality lockdown and makes block/vsock/cgroup dependencies built in. After `olddefconfig`, it fails on missing required settings or any remaining module. Kernel build identity/time is fixed; guest source paths are remapped; binary architecture is checked. The Debian dynamic linker checks the source-built init's library compatibility during the image build.

The ext4 regression constructs two filesystems with equal content and independent inode times and requires identical hashes. A full clean image rebuild comparison still requires recorded evidence; cache reuse does not prove independent reproducibility. Kernel/guest repeatability and runtime functionality remain separate checks.

[Recorded x86_64 build evidence](../../docs/evidence/2026-10-14-x86_64-image-build.json) contains the actual source/context pins, kernel/rootfs/init digests and successful offline verification. Native aarch64 build and authenticated runtime acceptance are explicitly unrun.

The kernel source tarball and generated config are retained with artifacts for corresponding-source provenance. Linux license notices are in that source; Firecracker config inputs come from its Apache-2.0 repository. Its CI config does not imply production qualification. Debian retains package copyright/license notices under `/usr/share/doc`; Hudson is Apache-2.0, with dependency licenses in their locked source packages. This recipe performs no artifact publication.

## Artifacts and verification

`build-receipt.json` records source revision, context digest, manifest digest, rootfs digest and local Docker image ID. Retain its manifest digest in trusted operator configuration outside the artifact directory. The manifest has fixed artifact names/digests/sizes, required embedded `/init` and `/usr/local/libexec/hudson/sandbox-guest`, architecture, kernel/Firecracker versions, guest/bootstrap protocol versions and minimum disk requirement.

Verify before configuring a host:

```sh
python3 scripts/guest_image.py verify --architecture x86_64 \
  --directory /absolute/guest-image --manifest-sha256 TRUSTED_64_HEX_DIGEST
```

The verifier checks the externally retained manifest hash, every artifact, pinned recipe, architecture and kernel policy. It inspects both binaries **inside** ext4 with read-only debugfs, without mounting or executing guest bytes on the host. Rewriting an artifact hash cannot hide a missing embedded init/agent. The image contains no allocation identity; the [separate bootstrap device](../../docs/guest-bootstrap.md) supplies fresh credentials later.

Use the rootfs digest for the operator allowlist and `CreateRequest.image_digest`. Allocate at least 256 MiB disk for this image. Configure `kernel.bin` and `rootfs.ext4` as the existing guardian's separate artifacts with recorded hashes. The guardian verifies bytes again and copies the filesystem into each allocation's private writable disk. Verification is an explicit operator preflight; automatic manifest-driven API/host admission and smaller variants remain follow-up work. The API's 64 MiB resource floor does not imply that this image fits 64 MiB.

`make guest-image-check` runs integrity and unprivileged deterministic ext4/embedded-binary checks without Docker, a mount, a guest or KVM. The full builder needs exact pinned sources/images and local compiler/cache disk space. Real create/execute/upload/download/destroy acceptance requires controlled-host child-exit, empty-cgroup and disk-cleanup evidence.
