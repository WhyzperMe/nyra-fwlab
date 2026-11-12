#!/usr/bin/env python3
"""Alternate two NYRA releases over identical workloads on the same host."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct
import subprocess
import tempfile
import time
import zipfile
import zlib


def workloads(root):
    archive = root / "small-files.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        for index in range(512):
            stream.writestr(f"config/item-{index:04d}.txt", b"synthetic content\n")
    sparse = root / "sparse-flash.bin"
    with sparse.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024)
    hostile = root / "invalid-crcs.bin"
    size = 32 * 1024 * 1024
    header = bytearray(64)
    struct.pack_into(">I", header, 0, 0x27051956)
    struct.pack_into(">I", header, 12, size)
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    with hostile.open("wb") as stream:
        stream.write(b"prefix" + header * 20)
        stream.truncate(stream.tell() + size)
    return {"many_small_files": archive, "large_sparse": sparse, "hostile_crc": hostile}


def measure(binary, source, target, threads, timing, extract_filesystems=False):
    args = [str(binary), "--run-timeout-seconds", "120", "analyze", str(source),
            "-o", str(target), "--allow-partial", "--threads", str(threads), "--json"]
    if extract_filesystems:
        args.append("--extract-filesystems")
    if timing:
        args = ["/usr/bin/time", "-f", "%M", "-o", str(timing), *args]
    start = time.perf_counter()
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=125)
    seconds = time.perf_counter() - start
    if result.returncode:
        raise RuntimeError("analyze failed for one of the release/workload pairs")
    manifest = json.loads(result.stdout)
    artifact_identity = sorted(
        (record["path"], record["sha256"], record["source_start"], record["source_length"])
        for record in manifest["artifacts"]
    )
    return (seconds, int(timing.read_text().strip()) / 1024 if timing else None,
            (manifest["source"]["sha256"], artifact_identity))


def require_matching_output_identities(baseline, candidate):
    if baseline != candidate:
        raise RuntimeError("baseline and candidate source/artifact identities differ")
    return True


def summarize(samples, size):
    seconds = sorted(sample[0] for sample in samples)
    rss = [sample[1] for sample in samples if sample[1] is not None]
    median = statistics.median(seconds)
    return {"median_seconds": median, "p95_seconds": seconds[math.ceil(len(seconds) * .95) - 1],
            "max_peak_rss_mib": max(rss) if rss else None, "median_mib_per_second": size / (1024 ** 2) / median}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--firmware", type=Path)
    parser.add_argument("--extract-filesystems", action="store_true",
                        help="also extract the reference firmware in the Linux sandbox")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()
    if args.extract_filesystems and not args.firmware:
        parser.error("--extract-filesystems requires --firmware")
    if not 1 <= args.iterations <= 30 or not 1 <= args.threads <= 16:
        parser.error("iterations must be 1–30 and threads must be 1–16")
    binaries = {key: getattr(args, key).resolve(strict=True) for key in ("baseline", "candidate")}
    identities = {
        key: {"version": subprocess.check_output([binary, "--version"], text=True).strip(),
              "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        for key, binary in binaries.items()
    }
    results = {}
    with tempfile.TemporaryDirectory(prefix="nyra-compare-") as temp:
        root = Path(temp)
        timing = root / "rss.txt" if Path("/usr/bin/time").is_file() else None
        inputs = workloads(root)
        if args.firmware:
            inputs["reference_firmware"] = args.firmware.resolve(strict=True)
        for name, source in inputs.items():
            samples = {key: [] for key in binaries}
            outputs = {}
            for index in range(args.iterations + 1):
                order = list(binaries) if index % 2 == 0 else list(reversed(binaries))
                for key in order:
                    with tempfile.TemporaryDirectory(dir=root) as sample:
                        elapsed, rss, output = measure(binaries[key], source, Path(sample) / "work", args.threads, timing,
                                                       args.extract_filesystems and name == "reference_firmware")
                    if outputs.setdefault(key, output) != output:
                        raise RuntimeError("artifact identity changed between repeated runs")
                    if len(outputs) == 2:
                        require_matching_output_identities(outputs["baseline"], outputs["candidate"])
                    if index:
                        samples[key].append((elapsed, rss))
            same_source_artifacts = require_matching_output_identities(outputs["baseline"], outputs["candidate"])
            results[name] = {"bytes": source.stat().st_size, "source_sha256": outputs["candidate"][0],
                             "same_source_artifacts": same_source_artifacts,
                             **{key: summarize(values, source.stat().st_size) for key, values in samples.items()}}
    print(json.dumps({"schema_version": 1, "threads": args.threads, "iterations": args.iterations,
                      "binaries": identities, "workloads": results}, indent=2))


if __name__ == "__main__":
    main()
