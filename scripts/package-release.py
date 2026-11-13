#!/usr/bin/env python3
"""Package one checked native CLI; release artifacts stay outside the checkout."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile

TARGETS = {
    "x86_64-pc-windows-msvc": ("nyra-fw.exe", "zip"),
    "x86_64-unknown-linux-gnu": ("nyra-fw", "tar.gz"),
}
REPO = Path(__file__).resolve().parents[1]
MAX_BINARY_BYTES = 32 * 1024 * 1024
MAX_UNPACKED_BYTES = MAX_BINARY_BYTES + 1024 * 1024


def archive_bytes(files, kind, epoch):
    """Stable order, permissions, timestamps and ownership; no host paths."""
    output = io.BytesIO()
    if kind == "zip":
        stamp = time.gmtime(max(epoch, 315532800))[:6]
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data, mode in sorted(files):
                info = zipfile.ZipInfo(name, stamp)
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data, compresslevel=9)
    elif kind == "tar.gz":
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data, mode in sorted(files):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), mode, epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
    else:
        raise ValueError("unsupported archive format")
    return output.getvalue()


def atomic_write(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".nyra-package-", delete=False) as file:
            temporary = Path(file.name)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def package(binary, output, version, target, commit, epoch):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not 315532800 <= epoch <= 4354819198:
        raise ValueError("invalid source identity or timestamp")
    executable, kind = TARGETS[target]
    stem = f"nyra-fwlab-{version}-{target}"
    if binary.stat().st_size > MAX_BINARY_BYTES:
        raise ValueError("release executable exceeds 32 MiB")
    data = binary.read_bytes()
    binary_hash = hashlib.sha256(data).hexdigest()
    source = f"https://github.com/WhyzperMe/nyra-fwlab/tree/{commit}"
    instructions = (
        f"NYRA FWLab {version}\nAuthor: Whyzper.Me\nTarget: {target}\n\n"
        f"Extract the archive, then run {executable} --help.\n"
        f"Example: {executable} scan firmware.pkg --json\n"
        "In a Unix shell use ./nyra-fw; in PowerShell use .\\nyra-fw.exe.\n"
        "The CLI never executes recovered firmware or flashes devices.\n"
        "External Ghidra/SquashFS analysis requires a provisioned Linux/WSL host.\n"
        "Verify the downloaded archive against SHA256SUMS before use.\n\n"
        f"Source and documentation: {source}\n"
        "License: MIT (see LICENSE); external firmware retains its own rights.\n"
    ).encode("utf-8")
    build_info = (
        f"version={version}\ntarget={target}\nsource_commit={commit}\n"
        f"source_date_epoch={epoch}\nbinary_sha256={binary_hash}\n"
    ).encode("ascii")
    files = [(f"{stem}/{executable}", data, 0o755),
             (f"{stem}/LICENSE", (REPO / "LICENSE").read_bytes(), 0o644),
             (f"{stem}/README.txt", instructions, 0o644),
             (f"{stem}/BUILD-INFO.txt", build_info, 0o644)]
    archive = archive_bytes(files, kind, epoch)
    output.mkdir(parents=True, exist_ok=True)
    name = f"{stem}.{kind}"
    record = {
        "schema_version": 1, "version": version, "target": target,
        "source_commit": commit, "source_date_epoch": epoch,
        "archive": name, "size": len(archive),
        "sha256": hashlib.sha256(archive).hexdigest(), "binary_sha256": binary_hash,
    }
    atomic_write(output / name, archive)
    atomic_write(output / f"{stem}.json", (json.dumps(record, indent=2) + "\n").encode("utf-8"))
    return record


def assemble(records, output, version, commit):
    """Recheck the copied archives before publishing their common index."""
    if len(records) != len(TARGETS) or {r["target"] for r in records} != set(TARGETS):
        raise ValueError("release needs exactly one artifact for each qualified target")
    for record in records:
        target = record["target"]
        executable, kind = TARGETS[target]
        stem = f"nyra-fwlab-{version}-{target}"
        if (record["schema_version"] != 1 or record["version"] != version
                or record["source_commit"] != commit or record["archive"] != f"{stem}.{kind}"):
            raise ValueError("artifact source identity or file name mismatch")
        path = output / record["archive"]
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("release archive exceeds 32 MiB")
        data = path.read_bytes()
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("release archive checksum mismatch")
        expected = {f"{stem}/{name}" for name in [executable, "LICENSE", "README.txt", "BUILD-INFO.txt"]}
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if (set(archive.namelist()) != expected or len(members) != 4
                        or sum(m.file_size for m in members) > MAX_UNPACKED_BYTES
                        or any(m.flag_bits & 1 or not stat.S_ISREG(m.external_attr >> 16) for m in members)):
                    raise ValueError("unexpected archive contents")
                payload = archive.read(f"{stem}/{executable}")
        else:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
                unpacked = compressed.read(MAX_UNPACKED_BYTES + 1)
            if len(unpacked) > MAX_UNPACKED_BYTES:
                raise ValueError("release archive exceeds unpacked byte limit")
            with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
                members = archive.getmembers()
                if len(members) != 4 or {m.name for m in members} != expected or not all(m.isfile() for m in members):
                    raise ValueError("unexpected archive contents")
                payload = archive.extractfile(f"{stem}/{executable}").read()
        if hashlib.sha256(payload).hexdigest() != record["binary_sha256"]:
            raise ValueError("packaged executable checksum mismatch")
    document = {"schema_version": 1, "version": version, "source_commit": commit,
                "artifacts": sorted(records, key=lambda record: record["target"])}
    encoded = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    atomic_write(output / "release-manifest.json", encoded)
    sums = {record["archive"]: record["sha256"] for record in records}
    sums["release-manifest.json"] = hashlib.sha256(encoded).hexdigest()
    atomic_write(output / "SHA256SUMS", "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())).encode("ascii"))
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--binary", type=Path)
    mode.add_argument("--index", type=Path, nargs="+", help="assemble copied per-platform records")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(REPO):
        parser.error("release output must stay outside the source checkout")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO).strip():
        parser.error("release packaging requires a clean committed tree")
    version = re.search(r'^version = "([^"]+)"$', (REPO / "Cargo.toml").read_text(encoding="utf-8"), re.M).group(1)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, encoding="ascii").strip()
    if args.index:
        if len(args.index) != len(TARGETS) or any(path.stat().st_size > 65536 for path in args.index):
            parser.error("invalid artifact record count or size")
        print(json.dumps(assemble([json.loads(path.read_bytes()) for path in args.index],
                                  args.output.resolve(), version, commit), indent=2))
        return
    target = next(line[6:] for line in subprocess.check_output(
        ["rustc", "-vV"], encoding="utf-8").splitlines() if line.startswith("host: "))
    if target not in TARGETS:
        parser.error("this native platform is not release-qualified")
    actual = subprocess.check_output([str(args.binary.resolve(strict=True)), "--version"],
                                     encoding="utf-8", timeout=10).strip()
    if actual != f"nyra-fw {version}":
        parser.error("binary and source versions differ")
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=REPO))
    print(json.dumps(package(args.binary, args.output.resolve(), version, target, commit, epoch), indent=2))


if __name__ == "__main__":
    main()
