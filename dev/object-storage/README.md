# Local object storage fixture

Compose and unprivileged CI use this one build recipe for the official community
MinIO server and official `mc`. The old official registry image is no longer
anonymously accessible. This fixture requires no registry login, paid service,
AIStor license or provider substitution. It is for development and tests only;
the pinned community server is archived upstream and is not a supported
production distribution.

## Verified inputs

The source releases and build tools were inspected and the following archives
and public multi-architecture OCI manifests were independently downloaded and
hashed on 2026-10-13:

| Input | Immutable revision/digest | Source SHA-256 |
| --- | --- | --- |
| [MinIO RELEASE.2025-10-15T17-29-55Z](https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z) | `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a` | `45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841` |
| [mc RELEASE.2025-08-13T08-35-41Z](https://github.com/minio/mc/releases/tag/RELEASE.2025-08-13T08-35-41Z) | `7394ce0dd2a80935aded936b09fa12cbb3cb8096` | `95cd293c7119f16921a6dc515a1fb74a2227f19fd994b9c8b770a154e802ac44` |
| Go `1.24.8-bookworm` | `sha256:4ed690d6649d63c312b99a6120025ec79ce3b542968a37da53d6236c7c61a848` | OCI manifest digest |
| BusyBox `1.37.0` | `sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e` | OCI manifest digest |

Source archives use `https://codeload.github.com/minio/REPOSITORY/tar.gz/COMMIT`.
The Dockerfile verifies each archive before unpacking it. Go dependencies use
each upstream `go.mod`/`go.sum`, checksum verification, `-mod=readonly` and
`go mod verify`. `GOTOOLCHAIN=local` prevents a silently downloaded compiler.
Go 1.24.8 matches the server's toolchain requirement and exceeds mc's 1.23.10
requirement. Both binaries are static, built with trimmed paths and fixed
upstream version/commit metadata, without modifying upstream source. Base
images use immutable multi-architecture manifests, including amd64 and arm64.
Build inputs are reproducible; this does not claim a reproducible OCI image
digest across Docker engines or architectures.

MinIO and mc retain their upstream **AGPL-3.0-or-later** licenses. Their complete
source archives, including licenses, notices and dependency manifests, and the
build recipe remain under `/usr/share/minio-source` in the local image. BusyBox
has its own GPL license; Go/base-image dependencies retain their respective
licenses. This repository publishes no fixture image or binary. Redistribution
or a production use is a separate decision that must address the applicable
source and license obligations.

## Build and use

From the repository root:

```sh
docker build -t hudson-output-fixture ./dev/object-storage
docker compose up -d --wait minio
```

Compose uses the same recipe and preserves `minio-data`. Its API and console
bind to loopback. Existing local data is not reset or migrated by these commands.
`docker compose down` stops the development services and keeps volumes. Do not
use `down -v` to repair the fixture.

CI creates a fresh container without a volume, binds its API to an ephemeral
loopback port, creates two private test buckets with the built `mc`, and enables
versioning on one. It records the exact container ID before readiness checks;
the `always()` teardown removes only that ID and its ephemeral data.

With the same `HUDSON_TEST_S3_*` environment variables used by the Rust tests:

```sh
python3 scripts/smoke_object_storage.py
cargo test -p sandbox-artifacts -p sandbox-controller -p sandbox-api -p sandbox-store \
  output_minio -- --ignored --test-threads=1
```

The smoke verifies health, denied anonymous reads/writes/listing, authenticated
binary writes/reads, `If-None-Match`/`If-Match` failures and exact historical
version reads. It deletes only its random test keys and explicit versions.
The existing Rust suite independently verifies digests, publication fencing,
versioned cleanup and retirement. No storage assertion is skipped or weakened.

## Updating the fixture

Inspect the official source, licenses and Go requirements first. Resolve release
tags to commit objects (mc's tag is annotated), hash both commit archives and
verify anonymous access to each exact base-image digest. Update the Dockerfile
and this table together, then build and run the smoke and unchanged explicit
Rust integration suite. Never fall back to a mutable source/image or downloaded
unverified binary when an input becomes unavailable.
