#!/usr/bin/env python3
"""Compare NYRA structure findings against independently recorded source ranges."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

VALIDATED = {"structure_validated", "payload_verified"}
HEX = re.compile(r"[0-9a-f]{64}")
LABEL = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}")
MAX_INPUT = 512 * 1024 * 1024


def sha256(file, length):
    digest = hashlib.sha256()
    while length:
        block = file.read(min(length, 1024 * 1024))
        if not block:
            raise ValueError("short input while hashing")
        digest.update(block)
        length -= len(block)
    return digest.hexdigest()


def check_case(binary, root, case):
    name = case["id"]
    if not LABEL.fullmatch(name) or type(case["exhaustive"]) is not bool:
        raise ValueError("invalid case identifier or exhaustive flag")
    relative = Path(case["file"])
    source = (root / relative).resolve(strict=True)
    if relative.is_absolute() or not source.is_relative_to(root) or not source.is_file():
        raise ValueError("case file must be a regular file inside the corpus")
    size = source.stat().st_size
    if size > MAX_INPUT:
        raise ValueError("corpus input exceeds the CLI limit")
    expected, tiers = {}, {}
    if not isinstance(case["expected"], list) or len(case["expected"]) > 2048:
        raise ValueError("case reference count is out of bounds")
    with source.open("rb") as file:
        source_hash = sha256(file, size)
        if source_hash != case["sha256"]:
            raise ValueError("corpus source checksum differs")
        for claim in case["expected"]:
            kind, start, length = claim["kind"], claim["offset"], claim["extent"]
            if claim.get("status", "structure_validated") not in VALIDATED:
                raise ValueError("invalid reference status")
            key = kind, start
            if not LABEL.fullmatch(kind) or type(start) is not int or not 0 <= start < size or key in expected:
                raise ValueError("invalid or duplicate reference range")
            if length is not None:
                if type(length) is not int or not 0 < length <= size - start:
                    raise ValueError("invalid reference extent")
                file.seek(start)
                if not HEX.fullmatch(claim["sha256"]) or sha256(file, length) != claim["sha256"]:
                    raise ValueError("independent reference range checksum differs")
            expected[key] = length
            if "status" in claim:
                tiers[key] = claim["status"]
    run = subprocess.run(
        [str(binary), "--run-timeout-seconds", "120", "scan", str(source), "--candidates", "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=125, check=False,
    )
    if run.returncode:
        raise ValueError("scanner exited with failure")
    scan = json.loads(run.stdout)
    report = scan["candidates"]
    if scan["sha256"] != source_hash or report["source_sha256"] != source_hash or report["input_bytes"] != size:
        raise ValueError("scanner report source differs from the reference")
    found = [item for item in report["candidates"] if item["container"] is None and item["status"] in VALIDATED]
    actual = {(item["kind"], item["offset"]): item["extent"] for item in found}
    actual_tier = {(item["kind"], item["offset"]): item["status"] for item in found}
    def records(keys, values):
        return [{"kind": kind, "offset": offset, "extent": values[kind, offset]} for kind, offset in sorted(keys)]

    matched = {key for key in expected.keys() & actual.keys() if expected[key] == actual[key]}
    extras = records(actual.keys() - expected.keys(), actual)
    missing = records(expected.keys() - actual.keys(), expected)
    extent_mismatches = [
        {**record, "actual_extent": actual[record["kind"], record["offset"]]}
        for record in records((expected.keys() & actual.keys()) - matched, expected)
    ]
    status_mismatches = [
        {"kind": kind, "offset": offset, "expected_status": tiers[kind, offset], "actual_status": actual_tier[kind, offset]}
        for kind, offset in sorted(matched & tiers.keys())
        if tiers[kind, offset] != actual_tier[kind, offset]
    ]
    return {
        "id": name, "source_sha256": source_hash, "bytes": size, "exhaustive": case["exhaustive"],
        "matched": records(matched, expected), "missing": missing, "extent_mismatches": extent_mismatches,
        "status_mismatches": status_mismatches,
        "false_positives": extras if case["exhaustive"] else [],
        "unclassified": extras if not case["exhaustive"] else [],
        "budget_exhausted": report["budget_exhausted"],
        "pass": not (missing or extent_mismatches or status_mismatches or (case["exhaustive"] and extras) or report["budget_exhausted"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = args.manifest.resolve(strict=True)
        if not manifest.is_file() or manifest.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("manifest exceeds the input bound")
        spec = json.loads(manifest.read_bytes())
        cases = spec["cases"]
        if spec["schema_version"] != 1 or not 1 <= len(cases) <= 256:
            raise ValueError("unsupported manifest or case count")
        if len({case["id"] for case in cases}) != len(cases):
            raise ValueError("duplicate case identifier")
        results = [check_case(args.binary.resolve(strict=True), manifest.parent, case) for case in cases]
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        parser.exit(2, "Corpus validation could not complete. Check the manifest, input digests and scanner.\n")
    print(json.dumps({"schema_version": 2, "cases": results}, indent=2))
    return 0 if all(result["pass"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
