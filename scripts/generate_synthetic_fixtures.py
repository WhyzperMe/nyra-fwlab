#!/usr/bin/env python3
"""Generate small, deterministic firmware-container fixtures with Python stdlib."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import stat
import struct
import tarfile
import zipfile
from pathlib import Path


ZIP_MEMBERS = {
    "config/device.ini": b"[camera]\nmodel=synthetic\nnetwork=disabled\n",
    "bin/controller.bin": bytes(range(256)) * 4,
}
GZIP_PAYLOAD = (
    b"NYRA FWLab synthetic gzip payload\n"
    b"This content is inert test data and must never be executed or flashed.\n"
)
FIXED_ZIP_TIME = (2020, 1, 2, 3, 4, 6)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, document: object) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


class WriteOnlyZip(io.BytesIO):
    def seek(self, offset, whence=io.SEEK_SET):
        raise io.UnsupportedOperation("streamed ZIP output")


def make_zip(path: Path, compression: int, streamed: bool) -> None:
    destination = WriteOnlyZip() if streamed else path
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=compression,
        compresslevel=9 if compression == zipfile.ZIP_DEFLATED else None,
        allowZip64=False,
    ) as archive:
        for name, content in ZIP_MEMBERS.items():
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.extra = b""
            info.comment = b""
            archive.writestr(
                info,
                content,
                compress_type=compression,
                compresslevel=9 if compression == zipfile.ZIP_DEFLATED else None,
            )
    if isinstance(destination, WriteOnlyZip):
        path.write_bytes(destination.getvalue())


def verify_zip(path: Path, compression: int) -> None:
    with zipfile.ZipFile(path, mode="r") as archive:
        actual_names = archive.namelist()
        if actual_names != list(ZIP_MEMBERS):
            raise RuntimeError(f"unexpected ZIP members in {path}: {actual_names!r}")
        for info in archive.infolist():
            if info.compress_type != compression or info.file_size > 1024 * 1024:
                raise RuntimeError(f"unexpected ZIP metadata for {info.filename!r}")
            if archive.read(info) != ZIP_MEMBERS[info.filename]:
                raise RuntimeError(f"ZIP member content mismatch: {info.filename!r}")


def golden_for(path: Path) -> dict[str, object]:
    return {
        "firmware_sha256": sha256(path.read_bytes()),
        "files": [
            {
                "name": name,
                "status": "original_crc_ok",
                "size": len(content),
                "sha256": sha256(content),
            }
            for name, content in ZIP_MEMBERS.items()
        ],
    }


def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    variants = (
        ("stored", zipfile.ZIP_STORED, False),
        ("deflated", zipfile.ZIP_DEFLATED, False),
        ("streamed-stored", zipfile.ZIP_STORED, True),
        ("streamed-deflated", zipfile.ZIP_DEFLATED, True),
    )
    for label, compression, streamed in variants:
        archive_path = output_dir / f"stdlib-zip-{label}.zip"
        make_zip(archive_path, compression, streamed)
        verify_zip(archive_path, compression)
        write_json(output_dir / f"stdlib-zip-{label}-golden.json", golden_for(archive_path))

    gzip_path = output_dir / "stdlib-firmware.gz"
    with gzip_path.open("wb") as raw_file:
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=9, fileobj=raw_file, mtime=0
        ) as compressed:
            compressed.write(GZIP_PAYLOAD)
    if gzip.decompress(gzip_path.read_bytes()) != GZIP_PAYLOAD:
        raise RuntimeError("generated gzip payload does not match its expected bytes")
    with tarfile.open(output_dir / "stdlib-firmware.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in ZIP_MEMBERS.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def verify_gzip_output(path: Path) -> None:
    actual = path.read_bytes()
    expected = sha256(GZIP_PAYLOAD)
    if actual != GZIP_PAYLOAD:
        raise SystemExit(
            f"gzip output mismatch for {path}: expected SHA-256 {expected}, got {sha256(actual)}"
        )
    print(f"GZIP PAYLOAD PASS: {len(actual)} bytes, SHA-256 {expected}")


def verify_tar_output(path: Path) -> None:
    actual = {p.relative_to(path).as_posix(): p.read_bytes() for p in path.rglob("*") if p.is_file()}
    if actual != ZIP_MEMBERS:
        raise SystemExit("TAR member set or contents differ from the independent fixture")
    print(f"TAR PAYLOAD PASS: {len(actual)} raw members")


def verify_archive_structure(source: Path, report_path: Path) -> None:
    """Compare archive evidence with independent stdlib readers."""
    raw = source.read_bytes()
    if zipfile.is_zipfile(io.BytesIO(raw)):
        kind = "zip"
        state = "central_and_local_metadata_validated"
        end = len(raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = []
            for info in sorted(archive.infolist(), key=lambda info: info.header_offset):
                if info.is_dir():
                    continue
                name_size, extra_size = struct.unpack_from("<HH", raw, info.header_offset + 26)
                members.append({
                    "name": info.filename,
                    "header_offset": info.header_offset,
                    "payload_offset": info.header_offset + 30 + name_size + extra_size,
                    "stored_bytes": info.compress_size,
                    "declared_decoded_bytes": info.file_size,
                    "declared_payload_crc32": info.CRC,
                })
    else:
        kind = "tar"
        state = "tar_headers_and_member_bounds_validated"
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            entries = archive.getmembers()
            end = max(
                item.offset_data + (item.size + 511) // 512 * 512 for item in entries
            ) + 1024
            members = [
                {
                    "name": item.name,
                    "header_offset": item.offset,
                    "payload_offset": item.offset_data,
                    "stored_bytes": item.size,
                    "declared_decoded_bytes": item.size,
                    "declared_payload_crc32": None,
                }
                for item in entries if item.isfile()
            ]
    expected = {
        "schema_version": 1,
        "source_sha256": sha256(raw),
        "format": kind,
        "structural_state": state,
        "archive_bytes": end,
        "regular_members": members,
    }
    if json.loads(report_path.read_bytes()) != expected:
        raise SystemExit("archive structure differs from the independent stdlib readers")
    print(f"ARCHIVE STRUCTURE PASS: {kind}, {len(members)} regular members")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory to receive ZIP, gzip, and independently computed golden fixtures",
    )
    parser.add_argument(
        "--verify-gzip-output",
        type=Path,
        help="verify an extracted gzip payload against the generator's source bytes",
    )
    parser.add_argument("--verify-tar-output", type=Path, help="compare copied TAR member bytes")
    parser.add_argument(
        "--verify-archive-structure", type=Path, nargs=2, metavar=("SOURCE", "REPORT"),
        help="compare a ZIP or TAR structure report with stdlib offsets and metadata",
    )
    args = parser.parse_args()
    if not any((args.output_dir, args.verify_gzip_output, args.verify_tar_output, args.verify_archive_structure)):
        parser.error("provide a generation or verification option")
    if args.output_dir is not None:
        generate(args.output_dir)
    if args.verify_gzip_output is not None:
        verify_gzip_output(args.verify_gzip_output)
    if args.verify_tar_output is not None:
        verify_tar_output(args.verify_tar_output)
    if args.verify_archive_structure is not None:
        verify_archive_structure(*args.verify_archive_structure)


if __name__ == "__main__":
    main()
