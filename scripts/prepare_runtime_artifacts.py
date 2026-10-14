"""Prepare pinned development artifacts without sudo, archive extraction or overwrite."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request
from urllib.parse import urlsplit

EVIDENCE = Path(__file__).resolve().parents[1] / 'docs/evidence/2026-09-21-aarch64-boot.json'
BINARY_EVIDENCE = EVIDENCE.parent / '2026-09-21-aarch64-public-execute.json'
MAX_BYTES = 128 * 1024 * 1024


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise ValueError("download redirected outside HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(spec):
    if urlsplit(spec['url']).scheme != 'https':
        raise ValueError('artifact URL must use HTTPS')
    request = urllib.request.Request(spec['url'])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirects())
    with opener.open(request, timeout=30) as response:
        if not response.geturl().startswith('https://'):
            raise ValueError('download redirected outside HTTPS')
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != spec['sha256']:
        raise ValueError('artifact size or SHA-256 mismatch')
    return data


def binary_pins():
    evidence = json.loads(BINARY_EVIDENCE.read_text())
    def find(value):
        if isinstance(value, dict):
            if 'artifact_sha256' in value:
                return value['artifact_sha256']
            for child in value.values():
                result = find(child)
                if result is not None:
                    return result
        return None
    pins = find(evidence)
    if pins is None:
        raise ValueError('tracked binary pins unavailable')
    return pins


def select_binaries(data):
    names = {f'release-v1.17.0-aarch64/{kind}-v1.17.0-aarch64': kind
             for kind in ('firecracker', 'jailer')}
    pins = binary_pins()
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            if member.name not in names:
                continue
            if member.name in result or not member.isfile() or not 0 < member.size <= MAX_BYTES:
                raise ValueError('invalid or duplicate binary member')
            content = archive.extractfile(member).read()
            if hashlib.sha256(content).hexdigest() != pins[names[member.name]]:
                raise ValueError('extracted binary SHA-256 mismatch')
            result[member.name] = content
    if set(result) != set(names):
        raise ValueError('archive lacks expected binaries')
    return result


def prepare(destination, architecture, fetch=download):
    if architecture in ('arm64', 'ARM64'):
        architecture = 'aarch64'
    if architecture != 'aarch64':
        raise ValueError('only tracked aarch64 development artifacts are pinned; x86_64 is unsupported')
    destination = Path(destination)
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValueError('destination must be a new absolute path')
    parent = destination.parent.resolve(strict=True)
    if parent != destination.parent:
        raise ValueError('destination parent must be canonical')
    evidence = json.loads(EVIDENCE.read_text())['artifacts']
    binaries = select_binaries(fetch(evidence['firecracker_archive']))
    kernel = fetch(evidence['guest_kernel'])
    with tempfile.TemporaryDirectory(prefix='.hudson-artifacts-', dir=parent) as temporary:
        stage = Path(temporary) / 'artifacts'
        stage.mkdir(mode=0o700)
        for name, data in {**binaries, 'vmlinux-6.1.186': kernel}.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name in binaries else 0o644)
        # Reserve destination exclusively; never replace any pre-existing file/directory.
        destination.mkdir(mode=0o700)
        try:
            for path in stage.iterdir():
                shutil.move(str(path), destination)
        except OSError:
            raise ValueError("partial publication retained; inspect destination manually before retry") from None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--architecture', default=platform.machine())
    args = parser.parse_args()
    try:
        prepare(args.destination, args.architecture)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, 'Artifact preparation failed; inspect trusted configuration and any partial destination.\n')
