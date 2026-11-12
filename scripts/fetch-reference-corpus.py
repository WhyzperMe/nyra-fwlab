#!/usr/bin/env python3
"""Download the images of a reference manifest and verify each against its pinned SHA-256.

The manifest pins a reference digest and the independently annotated ranges. Only
HTTPS URLs on an allowed publisher host are fetched, redirects stay on that host, each
download is size-bounded, and a file appears in the output directory only after its
digest matched. Firmware is stored, never executed. Keep the output outside the repository.

    python3 scripts/fetch-reference-corpus.py tests/fixtures/reference/openwrt-unseen-25.12.6.json ~/nyra-corpus/real
    python3 scripts/check-corpus.py --binary target/release/nyra-fw --manifest ~/nyra-corpus/real/corpus.json
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"downloads.openwrt.org", "raw.githubusercontent.com"}
MAX_IMAGE_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 60
DOWNLOAD_SECONDS = 300
HEX = re.compile(r"[0-9a-f]{64}")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}")


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            check_url(newurl)
            if urllib.parse.urlparse(req.full_url).hostname != urllib.parse.urlparse(newurl).hostname:
                raise ValueError("redirect changes publisher")
        except ValueError as error:
            raise urllib.error.URLError("redirect leaves the allowed publisher URLs") from error
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url):
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.query or parsed.fragment):
        raise ValueError("source_url must be an HTTPS URL on an allowed publisher host")
    if parsed.hostname == "raw.githubusercontent.com" and not re.fullmatch(
            r"/raspberrypi/firmware/[0-9a-f]{40}/boot/[A-Za-z0-9._-]+", parsed.path):
        raise ValueError("Raspberry Pi source must pin a full commit and boot file")


def download(opener, url, destination, expected):
    digest, size = hashlib.sha256(), 0
    partial = None
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    try:
        with opener.open(url, timeout=TIMEOUT_SECONDS) as response, tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", suffix=".part", delete=False,
        ) as out:
            partial = Path(out.name)
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("download exceeds its wall-clock budget")
                block = response.read1(1024 * 1024)
                if time.monotonic() >= deadline:
                    raise TimeoutError("download exceeds its wall-clock budget")
                if not block:
                    break
                size += len(block)
                if size > MAX_IMAGE_BYTES:
                    raise ValueError("download exceeds the size bound")
                digest.update(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        if digest.hexdigest() != expected:
            raise ValueError("SHA-256 differs from the pinned reference digest")
        os.replace(partial, destination)
    finally:
        if partial is not None:
            partial.unlink(missing_ok=True)
    return size


def cached_image_matches(path, expected):
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_IMAGE_BYTES:
            return False
        with path.open("rb") as image:
            digest, size = hashlib.sha256(), 0
            while block := image.read(1024 * 1024):
                size += len(block)
                if size > MAX_IMAGE_BYTES:
                    return False
                digest.update(block)
        return size == metadata.st_size and digest.hexdigest() == expected
    except FileNotFoundError:
        return False


def write_manifest(destination, document):
    partial = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=".corpus.", suffix=".part", delete=False,
        ) as out:
            partial = Path(out.name)
            out.write((json.dumps(document, indent=2) + "\n").encode("utf-8"))
            out.flush()
            os.fsync(out.fileno())
        os.replace(partial, destination)
    finally:
        if partial is not None:
            partial.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path, help="directory outside the repository; created if absent")
    parser.add_argument("--only", action="append", default=[], help="fetch only this case id (repeatable)")
    args = parser.parse_args()
    if args.manifest.stat().st_size > 4 * 1024 * 1024:
        parser.error("manifest exceeds the size bound")
    spec = json.loads(args.manifest.read_bytes())
    cases = spec["cases"]
    if spec["schema_version"] != 1 or not 1 <= len(cases) <= 256:
        parser.error("unsupported manifest")
    identifiers = [case["id"] for case in cases]
    names = [case["file"] for case in cases]
    if len(set(identifiers)) != len(cases) or len({name.casefold() for name in names}) != len(cases):
        parser.error("duplicate case id or file name")
    if set(args.only) - set(identifiers):
        parser.error("--only names an unknown case")
    cases = [case for case in cases if not args.only or case["id"] in args.only]
    for case in cases:
        name = case["file"]
        if (not FILE.fullmatch(name) or name.endswith(".")
                or name.split(".")[0].upper() in {
                    "CON", "PRN", "AUX", "NUL",
                    *(f"COM{i}" for i in range(1, 10)),
                    *(f"LPT{i}" for i in range(1, 10)),
                } or not HEX.fullmatch(case["sha256"])):
            parser.error("invalid file name or digest")
        try:
            check_url(case["source_url"])
        except ValueError as error:
            parser.error(str(error))
    args.output.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(SameHostRedirect)
    failures = 0
    for case in cases:
        name, expected = case["file"], case["sha256"]
        destination = args.output / name
        try:
            check_url(case["source_url"])
            if cached_image_matches(destination, expected):
                print(f"present  {expected}  {name}")
                continue
            size = download(opener, case["source_url"], destination, expected)
            print(f"verified {expected}  {name}  {size} bytes")
        except (OSError, ValueError, urllib.error.URLError) as error:
            failures += 1
            print(f"FAILED   {name}: {error}")
    if not failures:
        write_manifest(args.output / "corpus.json", {**spec, "cases": cases})
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
