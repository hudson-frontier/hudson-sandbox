# Development/CI only. See README.md here for provenance and licenses.
FROM golang:1.24.8-bookworm@sha256:4ed690d6649d63c312b99a6120025ec79ce3b542968a37da53d6236c7c61a848 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
RUN curl --fail --location --proto '=https' --proto-redir '=https' \
      https://codeload.github.com/minio/minio/tar.gz/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a -o minio.tar.gz \
    && echo '45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841  minio.tar.gz' | sha256sum -c - \
    && mkdir minio && tar -xzf minio.tar.gz --strip-components=1 -C minio \
    && curl --fail --location --proto '=https' --proto-redir '=https' \
      https://codeload.github.com/minio/mc/tar.gz/7394ce0dd2a80935aded936b09fa12cbb3cb8096 -o mc.tar.gz \
    && echo '95cd293c7119f16921a6dc515a1fb74a2227f19fd994b9c8b770a154e802ac44  mc.tar.gz' | sha256sum -c - \
    && mkdir mc && tar -xzf mc.tar.gz --strip-components=1 -C mc
WORKDIR /src/minio
RUN go mod download && go mod verify \
    && go build -trimpath -buildvcs=false -o /out/minio -ldflags '\
      -s -w \
      -X github.com/minio/minio/cmd.Version=2025-10-15T17:29:55Z \
      -X github.com/minio/minio/cmd.ReleaseTag=RELEASE.2025-10-15T17-29-55Z \
      -X github.com/minio/minio/cmd.CopyrightYear=2025 \
      -X github.com/minio/minio/cmd.CommitID=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a \
      -X github.com/minio/minio/cmd.ShortCommitID=9e49d5e7a648f' .
WORKDIR /src/mc
RUN go mod download && go mod verify \
    && go build -trimpath -buildvcs=false -o /out/mc -ldflags '\
      -s -w \
      -X github.com/minio/mc/cmd.Version=2025-08-13T08:35:41Z \
      -X github.com/minio/mc/cmd.ReleaseTag=RELEASE.2025-08-13T08-35-41Z \
      -X github.com/minio/mc/cmd.CopyrightYear=2025 \
      -X github.com/minio/mc/cmd.CommitID=7394ce0dd2a80935aded936b09fa12cbb3cb8096 \
      -X github.com/minio/mc/cmd.ShortCommitID=7394ce0dd2a80' .

FROM busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
COPY --from=build /out/minio /out/mc /usr/bin/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Retain corresponding source, notices and recipe in this local image.
COPY --from=build /src/minio.tar.gz /src/mc.tar.gz /usr/share/minio-source/
COPY Dockerfile /usr/share/minio-source/Dockerfile
LABEL org.opencontainers.image.title="Hudson local MinIO fixture" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      io.hudson.minio.revision="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a" \
      io.hudson.mc.revision="7394ce0dd2a80935aded936b09fa12cbb3cb8096"
EXPOSE 9000 9001
# CI data stays in the invocation-owned container; Compose owns its volume.
ENTRYPOINT ["minio"]
CMD ["server", "/data"]
