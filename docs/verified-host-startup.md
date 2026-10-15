# Start the host with verified guest images

The [verified launcher](../scripts/launch_verified_host.py) runs the existing full image verifier before starting the existing Linux `sandbox-host`. It connects the [pinned image recipe](../dev/guest-image/README.md) to an operator startup path for [#108](https://github.com/hudson-frontier/hudsonbox/issues/108). A missing/tampered manifest, wrong architecture, missing embedded init/agent, mismatched configured image or understated capability disk floor prevents host startup.

This validates image integrity and configuration handoff. It does not establish guest readiness, hardware isolation, network enforcement or pause/resume. Native aarch64 build and authenticated real-workload/physical-cleanup acceptance remain pending. The original host binary is still available for explicitly unqualified development; use this verified path for the pinned workload images.

## Operator inputs

Use trusted source-built launcher/verifier code and a trusted, SHA-256-pinned `sandbox-host` executable. Keep image bundles on a canonical native Linux path controlled by the service operator, with all exported files and `manifest.json` retained. The launcher requires owned regular files, no symlinks, no group/world writes and protected parent directories. Root startup therefore requires root-owned inputs. Existing writable shared/Windows mounts are unsuitable for privileged verified startup; development verification remains separate from supported-host qualification.

The normal [host configuration](real-supervisor.md) must map each rootfs `sha256:` ID to exactly the verified bundle's `kernel.bin` and `rootfs.ext4` paths and raw SHA-256 values. It still contains the explicit host ID/epoch, state/cgroup paths, guardian/runtime artifacts, capacity and optional [capabilities](host-capabilities.md). The launcher does not issue an epoch, install cgroups/networking, add authority, run migrations or silently change that configuration.

Create a private owned `0600` image-policy JSON file outside the artifact directory/source control:

```json
{
  "version": 1,
  "images": [
    {
      "directory": "/var/lib/hudson/images/BUILD_ID",
      "manifest_sha256": "REPLACE_WITH_EXTERNALLY_RETAINED_MANIFEST_SHA256"
    }
  ]
}
```

Use the trusted `build-receipt.json`/retained build record for the expected manifest hash. Do not approve a modified image by recalculating its expected hash after a verification failure. Every configured image needs one verified manifest; extra/unverified mappings and duplicate digests fail. The existing verifier checks all fixed artifact bytes, source/compatibility pins, architecture, hardening config and both binaries inside ext4 with read-only debugfs. No guest bytes are mounted or executed on the host.

An enrolled capability contract must advertise exactly those verified rootfs/kernel pairs, the compatible guest/bootstrap/wire/Firecracker versions and a disk minimum at least as large as the manifest requires. Enrollment, freshness and host resource admission remain the separate authenticated [capability contract](host-capabilities.md).

## Check without starting anything

Python 3.11+ and e2fsprogs/debugfs are needed. Check mode may use the operator's unprivileged account when it owns the inputs. Cross-architecture integrity checks may specify `--architecture`; actual startup requires the native Linux architecture.

```sh
python3 scripts/launch_verified_host.py \
  --config /private/host.json --image-policy /private/image-policy.json \
  --architecture x86_64 --check-only
```

The JSON result says `guest_images_verified` and lists image digests. It does not say the host or a VM is ready, and omits configuration/credential contents.

## Start the existing host

Run under the Linux operator account required by the real supervisor. Supply the known executable hash and its ordinary mTLS/reader/storage arguments after `--`:

```sh
python3 scripts/launch_verified_host.py \
  --config /private/host.json --image-policy /private/image-policy.json \
  --host-binary /usr/local/libexec/hudson/sandbox-host \
  --host-sha256 REPLACE_WITH_TRUSTED_HOST_BINARY_SHA256 \
  -- --listen 127.0.0.1:7443 \
  --ca-cert /private/ca.pem --server-cert /private/host.pem --server-key /private/host.key \
  --controller-cert-sha256 REPLACE_WITH_CONTROLLER_LEAF_SHA256
```

Verification uses one private read of the original host configuration. The launcher writes those exact bytes to an owned `0600` snapshot in a protected temporary directory and passes that snapshot to the pinned binary. Re-reading an original file before/after verification would permit an A-to-B-to-A configuration race; the verified bytes must be the bytes launched. Forwarded arguments cannot replace `--config`. No shell is involved.

The process stays in the foreground, forwards SIGINT/SIGTERM only to its owned host child and removes the temporary snapshot after that process exits. The original configuration, artifacts, host journal, allocation data and database remain. Stopping the supervisor is not verified VM destruction: existing guardians/leases and controller reconciliation still own cleanup. Use explicit authenticated destroy and its release evidence before maintenance or resource reuse.

## Checkout portability and validation

Text recipe inputs are normalized to LF before entering the Docker build context. Exported hardening text is canonical, and verification compares canonical recipe text while still checking every exported artifact against its exact manifest hash. A CRLF checkout cannot invalidate an otherwise identical pinned bundle. LF attributes cover Linux recipe/configuration files and shell scripts.

`make host-image-check guest-image-check` exercises private files, changed original configurations, snapshot-parent safety, manifest/mapping/capability failures, argument override denial, actual ext4 embedded binaries and a CRLF-checkout regression. The [recorded development evidence](evidence/2026-10-14-verified-host-launch.json) captures full verification of the existing pinned x86_64 bundle and handoff/shutdown through an owned test executable; no real host or VM was started. These checks do not replace the controlled-host acceptance set.
