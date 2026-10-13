#!/usr/bin/env python3
"""Exercise a private, loopback-only fixture using signed S3 requests.

Uses the HUDSON_TEST_S3_* variables shared with the Rust integration suite.
Deletes only random keys/versions created by this invocation. No third-party
Python packages, ambient credentials, proxies or automatic retries.
"""

import datetime
import hashlib
import hmac
import http.client
import ipaddress
import os
import re
import urllib.parse
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Fixture:
    def __init__(self):
        endpoint = urllib.parse.urlsplit(os.environ["HUDSON_TEST_S3_ENDPOINT"])
        require(
            endpoint.scheme == "http"
            and endpoint.hostname is not None
            and ipaddress.ip_address(endpoint.hostname).is_loopback
            and endpoint.username is None
            and endpoint.password is None
            and endpoint.path in ("", "/")
            and not endpoint.query
            and not endpoint.fragment,
            "fixture endpoint must be a literal loopback HTTP origin",
        )
        self.host = endpoint.hostname
        self.port = endpoint.port or 80
        self.authority = endpoint.netloc
        self.access_key = os.environ["HUDSON_TEST_S3_ACCESS_KEY"]
        self.secret_key = os.environ["HUDSON_TEST_S3_SECRET_KEY"]
        self.bucket = os.environ["HUDSON_TEST_S3_BUCKET"]
        self.versioned_bucket = os.environ["HUDSON_TEST_S3_VERSIONED_BUCKET"]
        for bucket in (self.bucket, self.versioned_bucket):
            require(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket), "invalid fixture bucket")
        require(self.bucket != self.versioned_bucket, "fixture buckets must be distinct")

    def request(self, method, path, body=b"", headers=None, query=None, signed=True):
        query_string = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
            for k, v in sorted((query or {}).items())
        )
        request_headers = {k.lower(): v for k, v in (headers or {}).items()}
        if signed:
            now = datetime.datetime.now(datetime.timezone.utc)
            stamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
            digest = hashlib.sha256(body).hexdigest()
            request_headers.update({"host": self.authority, "x-amz-date": stamp, "x-amz-content-sha256": digest})
            names = ";".join(sorted(request_headers))
            canonical_headers = "".join(f"{k}:{request_headers[k]}\n" for k in sorted(request_headers))
            canonical = "\n".join((method, path, query_string, canonical_headers, names, digest))
            scope = f"{day}/us-east-1/s3/aws4_request"
            to_sign = f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
            signing_key = ("AWS4" + self.secret_key).encode()
            for part in (day, "us-east-1", "s3", "aws4_request"):
                signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
            signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
            request_headers["authorization"] = (
                f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, SignedHeaders={names}, Signature={signature}"
            )
        connection = http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            target = path + ("?" + query_string if query_string else "")
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            data = response.read(65537)
            require(len(data) <= 65536, "fixture response exceeded smoke bound")
            return response.status, dict((k.lower(), v) for k, v in response.getheaders()), data
        finally:
            connection.close()


def smoke():
    fixture = Fixture()
    require(fixture.request("GET", "/minio/health/live", signed=False)[0] == 200, "fixture health failed")
    key = "hudson-smoke-" + uuid.uuid4().hex
    plain = f"/{fixture.bucket}/{key}"
    versioned = f"/{fixture.versioned_bucket}/{key}"
    versions = []
    plain_created = False
    try:
        for bucket in (fixture.bucket, fixture.versioned_bucket):
            require(fixture.request("GET", f"/{bucket}", signed=False)[0] == 403, "bucket permits anonymous listing")
        require(fixture.request("PUT", plain, b"unauthorized", signed=False)[0] == 403, "anonymous write permitted")
        status, headers, _ = fixture.request("PUT", plain, b"first\x00bytes", {"if-none-match": "*"})
        require(status == 200, "authenticated conditional write failed")
        plain_created = True
        etag = headers["etag"]
        require(fixture.request("PUT", plain, b"overwrite", {"if-none-match": "*"})[0] == 412, "existing key did not reject conditional overwrite")
        require(fixture.request("GET", plain, signed=False)[0] == 403, "anonymous read permitted")
        require(fixture.request("GET", plain, headers={"if-match": '"wrong-etag"'})[0] == 412, "mismatched digest precondition accepted")
        status, _, data = fixture.request("GET", plain, headers={"if-match": etag})
        require(status == 200 and data == b"first\x00bytes", "authenticated bytes changed")
        for body in (b"version-one", b"version-two"):
            status, headers, _ = fixture.request("PUT", versioned, body)
            require(status == 200, "versioned write failed")
            version = headers.get("x-amz-version-id")
            require(version and version != "null", "bucket versioning is not enabled")
            versions.append(version)
        require(versions[0] != versions[1], "version identity reused")
        for version, expected in zip(versions, (b"version-one", b"version-two")):
            status, _, data = fixture.request("GET", versioned, query={"versionId": version})
            require(status == 200 and data == expected, "pinned version read changed")
        print("Object storage smoke passed: private buckets, authenticated binary I/O, conditional writes and versioned reads.")
    finally:
        for version in versions:
            require(fixture.request("DELETE", versioned, query={"versionId": version})[0] == 204, "smoke version cleanup failed")
        if plain_created:
            require(fixture.request("DELETE", plain)[0] == 204, "smoke key cleanup failed")


if __name__ == "__main__":
    smoke()
