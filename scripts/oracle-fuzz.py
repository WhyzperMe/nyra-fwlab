#!/usr/bin/env python3
"""Differential fuzzing of the candidate scanner against the independent oracle.

Seed images are mutated deterministically (bit flips, truncation, insertion, deletion,
zeroing, duplication, splicing). Each mutant is scanned by NYRA FWLab and annotated by
`independent-oracle.py`, which uses no NYRA code. A mutant on which the two disagree about
a validated structure (kind, offset, extent or evidence tier) is kept for triage.

Not every disagreement is a defect. The oracle reads further than the scanner in places, and
the scanner applies format rules that the oracle's tools do not enforce. Each such difference
is a named class with a check that decides it, for example zero padding or an empty root name in a DTB. Only an
unexplained disagreement keeps its mutant and fails the run. Firmware is read, never executed.

    python3 scripts/oracle-fuzz.py --binary target/release/nyra-fw --seeds DIR --output DIR --count 2000
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oracle", HERE / "independent-oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

MAX_SEED_BYTES = 4 * 1024 * 1024
ORACLE_KINDS = set(oracle.SIGNATURES) - {"elf"}
VALIDATED = {"structure_validated", "payload_verified"}


def mutate(rng, data, seeds):
    """Apply one to three edits. Edits favour the first bytes, where headers live."""
    data = bytearray(data)
    names = []
    for _ in range(rng.randint(1, 3)):
        kind = rng.choice(["flip", "flip_header", "truncate", "insert", "delete", "zero", "duplicate", "splice"])
        names.append(kind)
        if not data:
            break
        size = len(data)
        at = rng.randrange(size)
        if kind == "flip":
            data[at] ^= 1 << rng.randrange(8)
        elif kind == "flip_header":
            at = rng.randrange(min(size, 128))
            data[at] ^= 1 << rng.randrange(8)
        elif kind == "truncate":
            del data[max(1, at):]
        elif kind == "insert":
            data[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        elif kind == "delete":
            del data[at:at + rng.randint(1, 16)]
        elif kind == "zero":
            data[at:at + rng.randint(1, 64)] = bytes(min(64, size - at))
        elif kind == "duplicate":
            span = data[at:at + rng.randint(1, 256)]
            data[at:at] = span
        else:
            other = rng.choice(seeds)
            start = rng.randrange(max(1, len(other)))
            data[at:at + 1] = other[start:start + rng.randint(1, 512)]
        if len(data) > MAX_SEED_BYTES:
            del data[MAX_SEED_BYTES:]
    return bytes(data), names


def scanner_report(binary, path):
    run = subprocess.run([str(binary), "--run-timeout-seconds", "60", "scan", str(path), "--candidates", "--json"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=70, check=False)
    if run.returncode:
        return None
    return json.loads(run.stdout)["candidates"] or {"candidates": []}


def findings_of(report):
    return {
        (c["kind"], c["offset"], c["extent"], c["status"])
        for c in report["candidates"]
        if c["container"] is None and c["status"] in VALIDATED and c["kind"] in ORACLE_KINDS
    }


# NYRA checks that apply a rule of the DTB specification (DTSpec 5.2 to 5.4) which dtc and
# libfdt do not enforce: the memory reservation block ends with a zero entry, the blocks do
# not overlap the header or each other, only versions 16 and 17 are read, property names are
# not empty, the root node is unnamed, padding after names and values is zero and a
# version 17 structure block ends with the FDT_END token.
FDT_SPEC_CHECKS = {
    "fdt_version", "fdt_block_bounds_and_alignment", "fdt_block_overlap",
    "fdt_reservation_terminator", "fdt_property_name", "fdt_structure_tokens",
}


def fdt_breaks_a_structure_rule(blob):
    """Independent walk of the structure block for DTSpec 5.4 rules that dtc and libfdt skip.

    The root node's name is the empty string, padding after names and values is zero, and a
    version 17 structure block ends with the FDT_END token.
    """
    structure, size = struct.unpack(">I", blob[8:12])[0], struct.unpack(">I", blob[36:40])[0]
    block, at, depth = blob[structure:structure + size], 0, 0
    while at + 4 <= len(block):
        token = struct.unpack(">I", block[at:at + 4])[0]
        at += 4
        if token == 1:
            end = block.find(b"\0", at)
            if end < 0:
                return False
            if depth == 0 and end != at:
                return True
            depth += 1
            padded = (end + 4) & ~3
            if any(block[end + 1:padded]):
                return True
            at = padded
        elif token == 2:
            depth -= 1
        elif token == 3:
            length = struct.unpack(">I", block[at:at + 4])[0]
            padded = (at + 8 + length + 3) & ~3
            if any(block[at + 8 + length:padded]):
                return True
            at = padded
        elif token == 9:
            version = struct.unpack(">I", blob[20:24])[0]
            return version == 17 and at != len(block)
    return False


def explain(side, finding, report, data, path, theirs):
    """Name the documented reason for a disagreement, or None if it is unexplained."""
    kind, offset, _, _ = finding
    mine = [c for c in report["candidates"] if c["container"] is None and c["kind"] == kind and c["offset"] == offset]
    failed = mine[0]["checks"][-1]["name"] if mine and mine[0]["status"] == "rejected" else None
    if side == "oracle_only" and kind == "fdt" and failed in FDT_SPEC_CHECKS:
        if failed != "fdt_structure_tokens" or fdt_breaks_a_structure_rule(data[offset:offset + finding[2]]):
            return "fdt_dtb_spec_rule_not_enforced_by_dtc_or_libfdt"
    if side == "oracle_only" and kind == "squashfs" and failed == "squashfs_metadata_table_chains":
        # `unsquashfs -ll` never reads the export table or the unused fragment blocks.
        return "squashfs_tail_table_not_read_by_unsquashfs"
    if side == "oracle_only" and kind == "squashfs" and failed == "squashfs_table_offsets":
        # The root inode reference holds a 48-bit block address. `unsquashfs` and the kernel
        # keep only 32 bits of it, so bits 48 to 63 are ignored. The scanner checks them.
        root = struct.unpack("<Q", data[offset + 32:offset + 40])[0]
        if root >> 48:
            return "squashfs_root_inode_upper_bits_ignored_by_unsquashfs"
    if side == "scanner_only" and kind == "xz":
        # The oracle hides block streams that a validated SquashFS explains. If only the oracle
        # accepts that SquashFS, the scanner's explained rejection leaves them visible.
        if any(k == "squashfs" and start < offset < start + (length or 0) for k, start, length, _ in theirs):
            return "xz_stream_inside_a_squashfs_that_only_the_oracle_accepts"
    if side == "oracle_only" and kind == "xz":
        if any(c["kind"] == "squashfs" and c["status"] in VALIDATED and c["container"] is None
               and c["offset"] < offset < c["offset"] + (c["extent"] or 0) for c in report["candidates"]):
            return "xz_stream_inside_a_squashfs_that_unsquashfs_rejects"
    if side == "scanner_only" and kind == "squashfs":
        # The tables line up and `-stat` reads them, but a metadata block no longer decodes.
        # The scanner does not decompress metadata.
        if oracle.run(["unsquashfs", "-offset", str(offset), "-stat", str(path)]).returncode == 0:
            return "squashfs_metadata_content_not_decoded"
    if side == "scanner_only" and kind == "zip":
        try:
            zipfile.ZipFile(io.BytesIO(data[offset:offset + finding[2]]))
        except NotImplementedError:
            return "zip_version_needed_refused_by_python"
        except zipfile.BadZipFile as error:
            # The scanner compares records, not the type-length-value blocks inside the extra fields.
            if "Corrupt extra field" in str(error):
                return "zip_extra_field_not_parsed"
        except Exception:
            pass
    return None


def oracle_findings(path):
    _, found = oracle.annotate(path)
    return {(c["kind"], c["offset"], c["extent"], c["status"]) for c in found}


def check(index, seed_name, data, names, binary, output):
    with tempfile.TemporaryDirectory(prefix="oracle-fuzz-") as scratch:
        path = Path(scratch) / "mutant.bin"
        path.write_bytes(data)
        report = scanner_report(binary, path)
        if report is None:
            return index, "scanner_failed", None
        mine, theirs = findings_of(report), oracle_findings(path)
        if mine == theirs:
            return index, "agree", None
        classes = {}
        for side, items in (("scanner_only", mine - theirs), ("oracle_only", theirs - mine)):
            for item in items:
                classes[(side, item)] = explain(side, item, report, data, path, theirs)
    digest = hashlib.sha256(data).hexdigest()
    explained = all(classes.values())
    if not explained:
        (output / f"{digest}.bin").write_bytes(data)
    detail = {
        "sha256": digest, "seed": seed_name, "edits": names,
        "scanner_only": sorted(mine - theirs), "oracle_only": sorted(theirs - mine),
        "classes": sorted({name for name in classes.values() if name}),
    }
    return index, "explained" if explained else "disagree", detail


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--seeds", type=Path, required=True, help="directory of seed images (files up to 4 MiB are used)")
    parser.add_argument("--output", type=Path, required=True, help="new directory for disagreeing mutants and the report")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1, help="random seed; the same value reproduces the same mutants")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()
    if not 1 <= args.count <= 1_000_000 or not 1 <= args.workers <= 16:
        parser.error("count or workers out of bounds")
    seeds = {p.name: p.read_bytes() for p in sorted(args.seeds.iterdir())
             if p.is_file() and p.suffix != ".json" and 0 < p.stat().st_size <= MAX_SEED_BYTES}
    if not seeds:
        parser.error("no usable seed files")
    args.output.mkdir(parents=True, exist_ok=False)
    rng = random.Random(args.seed)
    names, blobs = list(seeds), list(seeds.values())
    jobs = []
    for index in range(args.count):
        name = rng.choice(names)
        data, edits = mutate(rng, seeds[name], blobs)
        jobs.append((index, name, data, edits))
    tally = {"agree": 0, "explained": 0, "disagree": 0, "scanner_failed": 0}
    unexplained, classes = [], {}
    with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(check, i, n, d, e, args.binary, args.output) for i, n, d, e in jobs]
        for future in concurrent.futures.as_completed(futures):
            _, verdict, detail = future.result()
            tally[verdict] += 1
            if verdict == "disagree":
                unexplained.append(detail)
            elif verdict == "explained":
                for name in detail["classes"]:
                    classes[name] = classes.get(name, 0) + 1
    unexplained.sort(key=lambda item: item["sha256"])
    report = {"schema_version": 1, "random_seed": args.seed, "mutants": args.count, **tally,
              "explained_by_class": dict(sorted(classes.items())), "disagreements": unexplained}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "disagreements"}))
    raise SystemExit(1 if tally["disagree"] or tally["scanner_failed"] else 0)


if __name__ == "__main__":
    main()
