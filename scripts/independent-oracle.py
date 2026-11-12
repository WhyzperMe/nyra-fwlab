#!/usr/bin/env python3
"""Annotate supported structures in a firmware image without using NYRA FWLab code.

Every structure is decided by an independent implementation: Python `zlib` and
for gzip, `zipfile` for ZIP, `unsquashfs` for SquashFS, `mkimage` and `zlib.crc32`
for legacy uImage, `dtc` and libfdt (`fdtget`) for FDT, the xz specification for stream headers and the
UBI specification (CRC-32 without final inversion) for UBI erase-counter headers. The output is a corpus case in the
format read by `check-corpus.py`.

The oracle reports an extent only when the independent decoder proves one. Hits
that a validated SquashFS explains (xz, bzip2 and zstd block streams) are
excluded, as documented in docs/candidates.md. Firmware is read, never executed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile
import zlib

MAX_INPUT = 512 * 1024 * 1024
MAX_HITS = 4096
MAX_DECODED = 128 * 1024 * 1024
TOOL_TIMEOUT = 60
PAYLOAD_VERIFIED = {"gzip", "uimage"}
LABEL = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}")

SIGNATURES = {
    "zip": b"PK\x05\x06",
    "squashfs": b"hsqs",
    "uimage": b"\x27\x05\x19\x56",
    "fdt": b"\xd0\x0d\xfe\xed",
    "gzip": b"\x1f\x8b\x08",
    "xz": b"\xfd7zXZ\x00",
    "ubi": b"UBI#",
    "elf": b"\x7fELF",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def hits(data, magic):
    found, at = [], data.find(magic)
    while at != -1 and len(found) < MAX_HITS:
        found.append(at)
        at = data.find(magic, at + 1)
    return found


def run(args, **kwargs):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TOOL_TIMEOUT, check=False, **kwargs)


def squashfs(path, data, at):
    """Return the filesystem size when `unsquashfs` can read the whole directory tree.

    `-stat` alone checks only the superblock. `-ll` also reads the inode, directory,
    fragment and id tables, which a copied superblock inside an interleaving
    container does not survive.
    """
    stat = run(["unsquashfs", "-offset", str(at), "-stat", str(path)])
    match = re.search(rb"Filesystem size (\d+) bytes", stat.stdout) if not stat.returncode else None
    if not match:
        return None
    size = int(match.group(1))
    if at + size > len(data):
        return None
    listing = run(["unsquashfs", "-offset", str(at), "-ll", str(path)])
    return size if listing.returncode == 0 else None


def uimage(data, at):
    head = data[at:at + 64]
    if len(head) < 64:
        return None
    size = struct.unpack(">I", head[12:16])[0]
    body = data[at + 64:at + 64 + size]
    if size == 0 or len(body) != size:
        return None
    zeroed = head[:4] + b"\0\0\0\0" + head[8:]
    if zlib.crc32(zeroed) != struct.unpack(">I", head[4:8])[0]:
        return None
    if zlib.crc32(body) != struct.unpack(">I", head[24:28])[0]:
        return None
    return 64 + size


def mkimage_agrees(data, at, extent):
    """Cross-check the header parse with U-Boot's own `mkimage -l`."""
    with tempfile.TemporaryDirectory() as scratch:
        probe = Path(scratch) / "probe.img"
        probe.write_bytes(data[at:at + extent])
        result = run(["mkimage", "-l", str(probe)])
    return result.returncode == 0


def fdt(data, at):
    head = data[at:at + 40]
    if len(head) < 40:
        return None
    total = struct.unpack(">I", head[4:8])[0]
    if not 40 <= total <= len(data) - at:
        return None
    with tempfile.TemporaryDirectory() as scratch:
        probe = Path(scratch) / "probe.dtb"
        probe.write_bytes(data[at:at + total])
        # `-f` ignores dtc's style lint (property-name characters). Structure errors still fail.
        result = run(["dtc", "-q", "-f", "-I", "dtb", "-O", "dts", "-o", "/dev/null", str(probe)])
        # dtc tolerates header values that libfdt refuses, such as a last_comp_version
        # above the version. Listing the root node applies libfdt's own header check.
        libfdt = run(["fdtget", "-l", str(probe), "/"])
    return total if result.returncode == 0 and libfdt.returncode == 0 else None


def zip_extra_has_zip64(extra):
    """True when a ZIP extra-field block carries the ZIP64 record (header id 1)."""
    at = 0
    while at + 4 <= len(extra):
        header_id, length = struct.unpack("<HH", extra[at:at + 4])
        if header_id == 1:
            return True
        at += 4 + length
    return False


def zip_central_tiles(data, end, size):
    """Check the end record and that the central entries tile the directory exactly.

    `zipfile` reads an entry whose length fields overrun the directory up to the
    directory's end and ignores the disk fields, so this is checked independently.
    The scope is a single-disk archive, as in APPNOTE 4.3.16.
    """
    disk, central_disk, on_disk, total = struct.unpack("<HHHH", data[end + 4:end + 12])
    if disk or central_disk or on_disk != total:
        return False
    position = end - size
    for _ in range(total):
        if position + 46 > end or data[position:position + 4] != b"PK\x01\x02":
            return False
        name_length, extra_length, comment_length = struct.unpack("<HHH", data[position + 28:position + 34])
        if struct.unpack("<H", data[position + 34:position + 36])[0]:
            return False
        position += 46 + name_length + extra_length + comment_length
        if position > end:
            return False
    return position == end


def zip_local_agrees(data, local, info):
    """Compare a local header with its central record, as APPNOTE 4.3.7 and 4.4 define them.

    With bit 3 set, the local CRC and sizes may be zero because a data descriptor follows.
    """
    fields = struct.unpack("<IHHHHHIIIHH", data[local:local + 30])
    signature, _, flags, method, _, _, crc, compressed, plain, name_length, _ = fields
    if signature != 0x04034B50 or flags != info.flag_bits or method != info.compress_type:
        return False
    if data[local + 30:local + 30 + name_length] != info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437"):
        return False
    if flags & 0x8:
        if not all(local_value in (0, central) for local_value, central in
                   ((crc, info.CRC), (compressed, info.compress_size), (plain, info.file_size))):
            return False
        return zip_descriptor_agrees(data, local, name_length, info)
    return (crc, compressed, plain) == (info.CRC, info.compress_size, info.file_size)


def zip_descriptor_agrees(data, local, name_length, info):
    """The classic data descriptor after the member must repeat the central CRC and sizes."""
    extra_length = struct.unpack("<H", data[local + 28:local + 30])[0]
    at = local + 30 + name_length + extra_length + info.compress_size
    if data[at:at + 4] == b"PK\x07\x08":
        at += 4
    return data[at:at + 12] == struct.pack("<III", info.CRC, info.compress_size, info.file_size)


def zip_span(data, end):
    """Return (start, length) of a classic ZIP whose end record is at `end`.

    The start is inferred from the central directory, as `zipfile` does for archives
    with prepended data. The records must agree: `zipfile` parses the central
    directory and reads each local header. Member checksums are payload evidence and
    are not part of the structure. Archives that use ZIP64 fields are outside the
    classic subset and are not annotated.
    """
    if end + 22 > len(data):
        return None
    size, offset = struct.unpack("<II", data[end + 12:end + 20])
    comment = struct.unpack("<H", data[end + 20:end + 22])[0]
    start, stop = end - size - offset, end + 22 + comment
    if start < 0 or stop > len(data) or data[start:start + 4] != b"PK\x03\x04":
        return None
    if not zip_central_tiles(data, end, size):
        return None
    try:
        # Cut at the end record so `zipfile` cannot pick a forged record from the comment.
        with zipfile.ZipFile(io.BytesIO(data[start:end + 22])) as archive:
            for info in archive.infolist():
                if zip_extra_has_zip64(info.extra) or 0xFFFFFFFF in (info.file_size, info.compress_size, info.header_offset):
                    return None
                local = start + info.header_offset
                name_length, extra_length = struct.unpack("<HH", data[local + 26:local + 30])
                if zip_extra_has_zip64(data[local + 30 + name_length:local + 30 + name_length + extra_length]):
                    return None
                if not zip_local_agrees(data, local, info):
                    return None
                if not info.flag_bits & 0x1:
                    archive.open(info).close()
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError, OverflowError, struct.error):
        return None
    return start, stop - start


def gzip_extent(data, at):
    """Bytes of the first gzip member at `at`, proven by zlib's CRC32 and ISIZE checks."""
    decoder = zlib.decompressobj(wbits=31)
    produced = 0
    position = at
    try:
        while not decoder.eof and position < len(data):
            block = data[position:position + 65536]
            produced += len(decoder.decompress(block))
            position += len(block)
            if produced > MAX_DECODED:
                return None
    except zlib.error:
        return None
    # `unused_data` holds only the surplus of the last block, so count from there.
    return position - at - len(decoder.unused_data) if decoder.eof else None


def xz_header(data, at):
    flags = data[at + 6:at + 8]
    if len(flags) < 2 or len(data) < at + 12:
        return False
    return zlib.crc32(flags) == struct.unpack("<I", data[at + 8:at + 12])[0] and flags[0] == 0 and flags[1] <= 0x0F


def ubi_header(data, at):
    head = data[at:at + 64]
    if len(head) < 64 or head[4] != 1 or head[5:8] != b"\0\0\0":
        return False
    vid, payload = struct.unpack(">II", head[16:24])
    if vid < 64 or payload <= vid or payload > 4 * 1024 * 1024:
        return False
    return (~zlib.crc32(head[:60])) & 0xFFFFFFFF == struct.unpack(">I", head[60:64])[0]


def annotate(path):
    data = path.read_bytes()
    found = []
    for kind, magic in SIGNATURES.items():
        for at in hits(data, magic):
            extent = None
            if kind == "zip":
                span = zip_span(data, at)
                if span:
                    found.append({"kind": "zip", "offset": span[0], "extent": span[1]})
                continue
            if kind == "squashfs":
                extent = squashfs(path, data, at)
                ok = extent is not None
            elif kind == "uimage":
                extent = uimage(data, at)
                ok = extent is not None and mkimage_agrees(data, at, extent)
            elif kind == "fdt":
                extent = fdt(data, at)
                ok = extent is not None
            elif kind == "gzip":
                extent = gzip_extent(data, at)
                ok = extent is not None
            elif kind == "xz":
                ok = xz_header(data, at)
            elif kind == "ubi":
                ok = ubi_header(data, at)
            else:
                # ELF extents depend on the file layout and are annotated by hand.
                ok = False
            if ok:
                found.append({"kind": kind, "offset": at, "extent": extent})
    # SquashFS accounts for the block streams inside it.
    spans = [(c["offset"], c["offset"] + c["extent"]) for c in found if c["kind"] == "squashfs"]
    found = [
        c for c in found
        if not (c["kind"] == "xz" and any(start < c["offset"] < stop for start, stop in spans))
    ]
    for claim in found:
        if claim["extent"] is not None:
            claim["sha256"] = sha256(data[claim["offset"]:claim["offset"] + claim["extent"]])
        # Only gzip and uImage carry a payload checksum that the scanner verifies.
        claim["status"] = "payload_verified" if claim["kind"] in PAYLOAD_VERIFIED else "structure_validated"
    found.sort(key=lambda c: (c["offset"], c["kind"]))
    return data, found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--id", required=True)
    parser.add_argument("--exhaustive", action="store_true")
    args = parser.parse_args()
    if not LABEL.fullmatch(args.id) or args.firmware.stat().st_size > MAX_INPUT:
        parser.error("invalid identifier or oversized input")
    data, found = annotate(args.firmware)
    case = {
        "id": args.id, "file": args.firmware.name, "sha256": sha256(data),
        "exhaustive": args.exhaustive, "expected": found,
    }
    print(json.dumps(case, indent=2))


if __name__ == "__main__":
    main()
