#!/usr/bin/env python3
"""Generate disposable synthetic cases using independent Python and system-tool fixtures."""
import argparse
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixtures = Path(__file__).resolve().parents[1] / "tests/fixtures/synthetic"
    cases = []
    payload = b"synthetic configuration\n" * 32
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        info = zipfile.ZipInfo("config.txt", (2024, 1, 1, 0, 0, 0))
        stream.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED)
    archive = archive.getvalue()
    with zipfile.ZipFile(io.BytesIO(archive)) as stream:
        assert stream.read("config.txt") == payload
    compressed = gzip.compress(payload, mtime=0)
    assert gzip.decompress(compressed) == payload
    xz = lzma.compress(payload)
    assert lzma.decompress(xz) == payload
    dtb = (fixtures / "synthetic-fdt.dtb").read_bytes()
    ubi = (fixtures / "synthetic-ubi-ec.bin").read_bytes()

    def add(name, parts, exhaustive=True):
        image = bytearray()
        expected = []
        for kind, part, extent in parts:
            if kind:
                item = {"kind": kind, "offset": len(image), "extent": len(part) if extent else None}
                if extent:
                    item["sha256"] = sha(part)
                expected.append(item)
            image.extend(part)
        filename = name + ".bin"
        (args.output / filename).write_bytes(image)
        cases.append({"id": name, "file": filename, "sha256": sha(image), "exhaustive": exhaustive, "expected": expected})

    gap = (None, b"\xff" * 8192, False)
    add("mixed-flash", [gap, ("zip", archive, True), gap, ("fdt", dtb, True), gap, ("gzip", compressed, True), gap])
    add("header-only", [gap, ("ubi", ubi, False), gap, ("xz", xz, False)])
    add("zip-truncated", [gap, (None, archive[:-1], False), gap])
    bad_gzip = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    add("bad-gzip-good-zip", [gap, (None, bad_gzip, False), gap, ("zip", archive, True)])
    add("bad-elf-good-zip", [(None, b"\x7fELF\xffopaque", False), ("zip", archive, True)])
    add("padding-only", [gap, (None, bytes(8192), False)])
    (args.output / "corpus.json").write_text(json.dumps({"schema_version": 1, "cases": cases}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
