#!/usr/bin/env python3
"""Generate a disposable corpus of valid, damaged, truncated and ambiguous images.

Components come from tools independent of NYRA FWLab: `mksquashfs` (all six
compressors), `mkimage` and `dtc` (legacy uImage and FIT), `mkfs.jffs2`,
`mkfs.ubifs` with `ubinize`, Info-ZIP `zip`, `7z`, `xz`, `gzip`, GNU `tar` and
Python's `zipfile`, `gzip` and `lzma`. Expectations come from construction. The
independent oracle must then agree before a case is written, so an error in this
script cannot silently become a reference.

The output goes to a directory outside the repository. Nothing is executed or flashed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

sys.dont_write_bytecode = True  # Importing the oracle must not leave a cache beside the scripts.
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oracle", HERE / "independent-oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

PAD = b"\xff" * 4096


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tier(kind):
    """Evidence tier the scanner reports for a validated structure of this kind."""
    return "payload_verified" if kind in oracle.PAYLOAD_VERIFIED else "structure_validated"


def tool(*args, cwd=None, stdin=None):
    result = subprocess.run(list(args), cwd=cwd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120)
    if result.returncode:
        raise SystemExit(f"tool failed: {args[0]}: {result.stderr.decode(errors='replace')[:300]}")
    return result.stdout


class Parts:
    """Sequence of byte parts. Parts with a kind become expected findings."""

    def __init__(self):
        self.data = bytearray()
        self.expected = []

    def add(self, blob, kind=None, extent=True, nested=()):
        if kind:
            self.expected.append({"kind": kind, "offset": len(self.data), "extent": len(blob) if extent else None})
        for kind_n, delta, length in nested:
            self.expected.append({"kind": kind_n, "offset": len(self.data) + delta, "extent": length})
        self.data.extend(blob)
        return self

    def gap(self, size=4096):
        self.data.extend(b"\xff" * size)
        return self


def squashfs(work, compressor):
    tree = Path(work) / f"tree-{compressor}"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc/config").write_bytes(b"synthetic configuration\n" * 64)
    (tree / "etc/banner").write_bytes(bytes(range(256)) * 8)
    out = Path(work) / f"{tree.name}.squashfs"
    command = ["mksquashfs", str(tree), str(out), "-comp", compressor, "-noappend", "-quiet", "-no-progress",
               "-all-time", "0", "-mkfs-time", "0", "-all-root", "-no-xattrs", "-b", "65536"]
    tool(*command)
    return out.read_bytes()


def squashfs_used(work, image):
    probe = Path(work) / "probe.squashfs"
    probe.write_bytes(image)
    return int(tool("unsquashfs", "-stat", str(probe)).split(b"Filesystem size ")[1].split(b" ")[0])


def uimage(work, payload, compression="none"):
    source = Path(work) / "kernel.bin"
    source.write_bytes(payload)
    out = Path(work) / "kernel.uimg"
    tool("mkimage", "-A", "arm", "-O", "linux", "-T", "kernel", "-C", compression, "-a", "0x80008000",
         "-e", "0x80008000", "-n", "synthetic", "-d", str(source), str(out))
    return out.read_bytes()


def fit(work, payload, external=False):
    (Path(work) / "kernel.bin").write_bytes(payload)
    its = Path(work) / "fit.its"
    its.write_text(
        '/dts-v1/;\n/ {\n description = "synthetic";\n #address-cells = <1>;\n images {\n'
        '  kernel-1 { description = "k"; data = /incbin/("kernel.bin"); type = "kernel"; arch = "arm";'
        ' os = "linux"; compression = "none"; load = <0x80008000>; entry = <0x80008000>; };\n };\n'
        ' configurations { default = "c1"; c1 { kernel = "kernel-1"; }; };\n};\n'
    )
    out = Path(work) / "fit.itb"
    tool("mkimage", *(["-E", "-B", "8"] if external else []), "-f", str(its), str(out), cwd=work)
    return out.read_bytes()


def zip_bytes(members, method=zipfile.ZIP_DEFLATED, zip64=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in members:
            info = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0))
            info.compress_type = method
            with archive.open(info, "w", force_zip64=zip64) as stream:
                stream.write(body)
    return buffer.getvalue()


def info_zip(work, members, *flags, stream=False):
    out = Path(work) / "info.zip"
    out.unlink(missing_ok=True)
    folder = Path(work) / "zipsrc"
    folder.mkdir(exist_ok=True)
    for name, body in members:
        (folder / name).write_bytes(body)
    names = [name for name, _ in members]
    if stream:
        # Standard input forces a data descriptor after the member.
        data = tool("zip", "-q", "-X", "-", "-", *flags, stdin=members[0][1])
        return data
    tool("zip", "-q", "-X", "-r", str(out), *names, *flags, cwd=folder)
    return out.read_bytes()


class _Sink(io.RawIOBase):
    """Unseekable sink: `zipfile` must then write a data descriptor after each member."""

    def __init__(self):
        self.buffer = bytearray()

    def writable(self):
        return True

    def write(self, chunk):
        self.buffer += chunk
        return len(chunk)


def streamed_zip(members):
    sink = _Sink()
    with zipfile.ZipFile(sink, "w") as archive:
        for name, body in members:
            info = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            with archive.open(info, "w") as stream:
                stream.write(body)
    return bytes(sink.buffer)


def flip(data, at):
    changed = bytearray(data)
    changed[at] ^= 0x01
    return bytes(changed)


def build(work):
    cases = []
    body = b"synthetic configuration\n" * 48
    kernel = (bytes(range(251)) * 400)
    members = [("config.txt", body), ("data.bin", bytes(range(256)) * 16)]

    def case(name, parts, exhaustive=True, notes=""):
        data = bytes(parts.data)
        cases.append({"id": name, "bytes": data, "exhaustive": exhaustive, "expected": parts.expected, "notes": notes})

    # --- Valid structures from families not covered by the earlier corpora ---
    gz_kernel = gzip.compress(kernel, mtime=0)
    ui_gz = uimage(work, gz_kernel, "gzip")
    images = {name: squashfs(work, name) for name in ("gzip", "lzma", "lzo", "xz", "lz4", "zstd")}
    for compressor, image in images.items():
        used = squashfs_used(work, image)
        case(f"squashfs-{compressor}", Parts().gap().add(image[:used], "squashfs").add(image[used:]).gap(), notes="SquashFS 4.0 little endian")
    sq_xz = images["xz"]
    used = squashfs_used(work, sq_xz)
    case("uimage-gzip-then-squashfs", Parts().add(ui_gz, "uimage", nested=[("gzip", 64, len(gz_kernel))]).gap().add(sq_xz[:used], "squashfs").gap(),
         notes="Router-style kernel and root file system")
    case("fit-embedded-data", Parts().add(fit(work, kernel), "fdt", nested=[]), notes="FIT with embedded kernel")
    external = fit(work, kernel, external=True)
    total = struct.unpack(">I", external[4:8])[0]
    case("fit-external-data", Parts().add(external[:total], "fdt").add(external[total:]), notes="External data stays outside the FDT extent")
    case("jffs2-neighbour", Parts().add(ui_gz, "uimage", nested=[("gzip", 64, len(gz_kernel))]).gap().add(
        jffs2(work)), notes="JFFS2 has no signature in this build; only the uImage is expected")
    image = ubi(work)
    blocks = [{"kind": "ubi", "offset": at, "extent": None} for at in range(0, len(image), 131072)]
    ubi_case = Parts().add(image)
    ubi_case.expected = blocks
    case("ubifs-ubinize", ubi_case, notes="One erase-counter header per 128 KiB erase block; no extent is proven")

    # --- ZIP families ---
    deflate = zip_bytes(members)
    case("zip-deflate", Parts().gap().add(deflate, "zip").gap())
    case("zip-stored", Parts().add(zip_bytes(members, zipfile.ZIP_STORED), "zip"))
    case("zip-data-descriptor-zip64", Parts().add(info_zip(work, members[:1], stream=True)), notes="Info-ZIP streams with ZIP64 descriptors. Outside the classic subset: no structure is expected")
    case("zip-streamed-descriptor", Parts().add(streamed_zip(members), "zip"), notes="Python zipfile on an unseekable stream: classic 32-bit data descriptors")
    case("zip-info-extra-fields", Parts().add(info_zip_default(work, members), "zip"), notes="Info-ZIP default extended timestamp and unix extra fields")
    case("zip-non-ascii-name", Parts().add(zip_bytes([("caf\u00e9.txt", body)]), "zip"), notes="UTF-8 member name")
    case("zip-unsafe-member-name", Parts().add(zip_bytes([("../escape.txt", body)]), "zip"), notes="Structurally valid. Extraction must refuse the name")
    case("zip-duplicate-member-names", Parts().add(duplicate_zip(body), "zip"), notes="Structurally valid. Extraction must refuse the collision")
    case("zip-directories-and-empty-member", Parts().add(zip_bytes([("dir/", b""), ("dir/empty", b""), ("dir/file", body)]), "zip"))
    case("zip-bzip2-members", Parts().add(zip_bytes(members, zipfile.ZIP_BZIP2), "zip"), notes="Consistent records with a method outside the decoder subset")
    case("zip-lzma-members", Parts().add(zip_bytes(members, zipfile.ZIP_LZMA), "zip"), notes="Consistent records with a method outside the decoder subset")
    case("zip-zip64-forced", Parts().add(zip_bytes(members, zip64=True)), notes="ZIP64 extra fields. Outside the classic subset: no structure is expected")
    case("zip-prefixed-unadjusted", Parts().add(b"MZ" + bytes(1022)).add(deflate, "zip"), notes="Self-extractor style prefix; offsets are relative to the archive start")
    adjusted = info_zip(work, members, "-0")
    prefix = b"#!stub\n" + bytes(1017)
    (Path(work) / "sfx.zip").write_bytes(prefix + adjusted)
    tool("zip", "-q", "-A", str(Path(work) / "sfx.zip"))
    sfx = (Path(work) / "sfx.zip").read_bytes()
    case("zip-prefixed-adjusted", Parts().add(sfx), notes="Info-ZIP -A rewrites offsets relative to the file start. The archive is not self-contained, so no standalone ZIP range is expected")
    case("zip-comment-contains-end-record", Parts().add(zip_with_comment(members, b"PK\x05\x06" + bytes(18)), "zip"))
    case("zip-trailing-bytes", Parts().add(deflate, "zip").add(b"TRAILER" * 8))
    case("zip-concatenated-pair", Parts().add(deflate, "zip").add(zip_bytes(members, zipfile.ZIP_STORED), "zip"), notes="Two archives back to back; each end record is relative to its own start")
    inner = zip_bytes([("inner.txt", b"inner payload\n" * 8)], zipfile.ZIP_STORED)
    nested_zip = zip_bytes([("firmware/inner.zip", inner)], zipfile.ZIP_STORED)
    inner_at = nested_zip.index(inner)
    case("zip-stored-nested-zip", Parts().add(nested_zip, "zip", nested=[("zip", inner_at, len(inner))]), notes="A stored member that is itself a ZIP")
    case("zip-stored-gzip-member", Parts().add(zip_bytes([("kernel.gz", gz_kernel)], zipfile.ZIP_STORED), "zip", nested=[("gzip", zip_bytes([("kernel.gz", gz_kernel)], zipfile.ZIP_STORED).index(gz_kernel), len(gz_kernel))]))

    # --- Compression families ---
    xz = lzma.compress(kernel)
    case("xz-stream", Parts().gap().add(xz, "xz", extent=False).gap())
    case("xz-two-streams", Parts().add(xz, "xz", extent=False).add(lzma.compress(body), "xz", extent=False))
    case("gzip-with-name-and-padding", Parts().add(gz_member(kernel, name=b"vmlinux"), "gzip").add(bytes(512)))
    case("gzip-two-members", Parts().add(gz_member(kernel), "gzip").add(gz_member(body), "gzip"))

    # --- Truncated and damaged variants of valid parents ---
    sq = sq_xz[:used]
    cut = {
        "truncated-squashfs-tail": Parts().gap().add(sq[:-1]),
        "truncated-squashfs-header": Parts().gap().add(sq[:60]),
        "truncated-uimage-payload": Parts().add(ui_gz[:-1]),
        "truncated-uimage-header": Parts().add(ui_gz[:40]),
        "truncated-gzip-trailer": Parts().add(gz_kernel[:-3]),
        "truncated-zip-central-directory": Parts().add(deflate[:-30]),
        "truncated-fdt": Parts().add(external[:total - 1]),
        "truncated-xz-header": Parts().add(xz[:8]),
        "truncated-ubi-header": Parts().add(ubi(work)[:48]),
    }
    for name, parts in cut.items():
        if name == "truncated-squashfs-tail":
            # The xz block streams stay visible once no validated image explains them.
            parts.expected = [{"kind": "xz", "offset": 4096 + at, "extent": None} for at in (96, 442)]
        case(name, parts, notes="Cut short. The damaged structure must not validate")
    flips = {
        "uimage-payload-crc-flipped": flip(ui_gz, len(ui_gz) - 1),
        "uimage-header-crc-flipped": flip(ui_gz, 5),
        "gzip-crc-flipped": flip(gz_kernel, len(gz_kernel) - 8),
        "gzip-isize-flipped": flip(gz_kernel, len(gz_kernel) - 1),
        "zip-member-crc-flipped": zip_crc_flip(deflate),
        "xz-header-crc-flipped": flip(xz, 8),
        "fdt-token-damaged": flip(external[:total], struct.unpack(">I", external[8:12])[0] + 3),
    }
    for name, data in flips.items():
        parts = Parts().add(data)
        if name == "zip-member-crc-flipped":
            # Member checksums are payload evidence. The records still agree, so the archive
            # is a structure-validated candidate and recovery reports the failed member.
            parts.expected = [{"kind": "zip", "offset": 0, "extent": len(data)}]
        if name == "uimage-header-crc-flipped":
            # The wrapped gzip member is still a complete stream of its own.
            parts.expected = [{"kind": "gzip", "offset": 64, "extent": len(gz_kernel)}]
        case(name, parts, notes="One bit changed. A checksummed structure must not validate; a ZIP stays structure-validated")
    sq_bad = bytearray(sq)
    struct.pack_into("<Q", sq_bad, 40, len(sq) + 4096)
    streams = [{"kind": "xz", "offset": at, "extent": None} for at in (96, 442)]
    parts = Parts().add(bytes(sq_bad))
    parts.expected = list(streams)
    case("squashfs-bytes-used-beyond-input", parts, notes="Declared size exceeds the input. The xz block streams are no longer explained by a validated image")
    sq_ver = bytearray(sq)
    struct.pack_into("<H", sq_ver, 28, 3)
    parts = Parts().add(bytes(sq_ver))
    parts.expected = list(streams)
    case("squashfs-version-3-header", parts, notes="Not a 4.0 superblock. The xz block streams are visible on their own")

    # --- Ambiguous layouts: overlap without containment ---
    overlap, ranges = overlapping_uimages()
    parts = Parts().add(overlap)
    parts.expected = [{"kind": "uimage", "offset": at, "extent": length} for at, length in ranges]
    case("uimage-overlap-without-containment", parts, notes="Two valid uImages whose extents overlap without containment. Neither may be carved")
    case("uimage-nested-valid", Parts().add(nested_uimage(work), "uimage", nested=[("uimage", 64 + 16, nested_len(work))]),
         notes="A complete uImage stored inside another uImage's payload")
    return cases


def jffs2(work):
    tree = Path(work) / "jffs2tree"
    tree.mkdir(exist_ok=True)
    (tree / "file").write_bytes(b"jffs2 payload\n" * 64)
    out = Path(work) / "out.jffs2"
    tool("mkfs.jffs2", "-r", str(tree), "-o", str(out), "-e", "128", "-l", "-n", "-q")
    return out.read_bytes()


def ubi(work):
    tree = Path(work) / "ubitree"
    tree.mkdir(exist_ok=True)
    (tree / "file").write_bytes(b"ubifs payload\n" * 64)
    ubifs = Path(work) / "out.ubifs"
    tool("mkfs.ubifs", "-r", str(tree), "-m", "2048", "-e", "126976", "-c", "32", "-o", str(ubifs))
    ini = Path(work) / "ubinize.ini"
    ini.write_text("[ubifs]\nmode=ubi\nimage=out.ubifs\nvol_id=0\nvol_type=dynamic\nvol_name=rootfs\nvol_flags=autoresize\n")
    out = Path(work) / "out.ubi"
    tool("ubinize", "-m", "2048", "-p", "128KiB", "-s", "512", "-O", "2048", "-o", str(out), str(ini), cwd=work)
    return out.read_bytes()


def info_zip_default(work, members):
    folder = Path(work) / "zipdefault"
    folder.mkdir(exist_ok=True)
    for name, data in members:
        (folder / name).write_bytes(data)
    out = Path(work) / "default.zip"
    out.unlink(missing_ok=True)
    tool("zip", "-q", str(out), *[name for name, _ in members], cwd=folder)
    return out.read_bytes()


def duplicate_zip(body):
    import warnings
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buffer, "w") as archive:
            for _ in range(2):
                archive.writestr(zipfile.ZipInfo("same.txt", (2024, 1, 1, 0, 0, 0)), body, zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


def zip_with_comment(members, comment):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in members:
            archive.writestr(zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0)), body, zipfile.ZIP_STORED)
        archive.comment = comment
    return buffer.getvalue()


def zip_crc_flip(archive):
    """Damage one stored payload byte inside a ZIP so the member CRC no longer matches."""
    stored = zip_bytes([("a.bin", b"A" * 64)], zipfile.ZIP_STORED)
    at = stored.index(b"A" * 64)
    return flip(stored, at)


def gz_member(payload, name=None):
    out = io.BytesIO()
    with gzip.GzipFile(filename=name.decode() if name else "", fileobj=out, mode="wb", mtime=0) as stream:
        stream.write(payload)
    return out.getvalue()


def header(payload, crc_payload=None, magic=0x27051956):
    fields = struct.pack(">IIIIIIIBBBB", magic, 0, 0, len(payload), 0x80008000, 0x80008000,
                         zlib.crc32(payload) if crc_payload is None else crc_payload, 5, 2, 2, 0) + b"overlap".ljust(32, b"\0")
    raw = bytearray(fields)
    raw[4:8] = struct.pack(">I", zlib.crc32(bytes(raw)))
    return bytes(raw)


def overlapping_uimages():
    """Image B starts inside A's payload and ends after A ends. Both CRCs verify."""
    payload_b = bytes(range(256)) * 4
    image_b = header(payload_b) + payload_b
    prefix = b"A" * 64
    payload_a = prefix + image_b[:len(image_b) // 2]
    image_a = header(payload_a) + payload_a
    start_b = 64 + len(prefix)
    blob = image_a[:start_b] + image_b
    return blob, [(0, len(image_a)), (start_b, len(image_b))]


def nested_len(work):
    payload = bytes(range(256)) * 2
    return 64 + len(payload)


def nested_uimage(work):
    inner_payload = bytes(range(256)) * 2
    inner = header(inner_payload) + inner_payload
    payload = b"P" * 16 + inner + b"S" * 16
    return header(payload) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory outside the repository")
    parser.add_argument("--skip-oracle", action="store_true", help="write cases without the independent cross-check")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest, disagreements = [], []
    with tempfile.TemporaryDirectory() as work:
        for item in build(work):
            filename = item["id"] + ".bin"
            path = args.output / filename
            path.write_bytes(item["bytes"])
            expected = [dict(claim) for claim in item["expected"]]
            for claim in expected:
                claim["status"] = tier(claim["kind"])
                if claim["extent"] is not None:
                    claim["sha256"] = sha(item["bytes"][claim["offset"]:claim["offset"] + claim["extent"]])
            if not args.skip_oracle:
                _, annotated = oracle.annotate(path)
                seen = {(c["kind"], c["offset"], c["extent"], c["status"]) for c in annotated}
                built = {(c["kind"], c["offset"], c["extent"], c["status"]) for c in expected}
                if seen != built:
                    disagreements.append({"id": item["id"], "construction_only": sorted(built - seen), "oracle_only": sorted(seen - built), "notes": item["notes"]})
            manifest.append({"id": item["id"], "file": filename, "sha256": sha(item["bytes"]), "exhaustive": item["exhaustive"], "expected": sorted(expected, key=lambda c: (c["offset"], c["kind"]))})
    (args.output / "corpus.json").write_text(json.dumps({"schema_version": 1, "cases": manifest}, indent=2) + "\n", encoding="utf-8")
    (args.output / "oracle-disagreements.json").write_text(json.dumps(disagreements, indent=2) + "\n", encoding="utf-8")
    print(f"{len(manifest)} cases written, {len(disagreements)} construction/oracle disagreements")
    raise SystemExit(1 if disagreements else 0)


if __name__ == "__main__":
    main()
