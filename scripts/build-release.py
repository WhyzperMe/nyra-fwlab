#!/usr/bin/env python3
"""Build the native release CLI with remapped source paths and check the artifact."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess


def path_mappings(repo, environment):
    home = Path.home()
    paths = {
        home: "/build-home",
        Path(environment.get("CARGO_HOME", home / ".cargo")).resolve(): "/cargo-home",
        Path(environment.get("RUSTUP_HOME", home / ".rustup")).resolve(): "/rustup-home",
        repo: "/nyra-fwlab",
    }
    mappings = []
    # Rust applies the last matching prefix, so specific directories follow parents.
    for path, replacement in sorted(paths.items(), key=lambda item: len(str(item[0]))):
        variants = {str(path), path.as_posix()}
        if os.name == "nt":
            variants |= {value.replace("/", "\\") for value in variants}
            variants |= {value[0].lower() + value[1:] for value in variants}
        mappings.extend((source, replacement) for source in sorted(variants))
    return mappings


def verify_binary(binary, mappings):
    data = binary.read_bytes()
    folded = data.lower()
    for source, _ in mappings:
        for encoding in ("utf-8", "utf-16le"):
            prefix = source.lower().encode(encoding)
            if folded.endswith(prefix) or any(
                (source.lower() + suffix).encode(encoding) in folded for suffix in ("/", "\\", "\0")
            ):
                raise ValueError("release binary contains a local build path")
    if re.search(rb"(?:[a-z]:[/\\]users[/\\]|/home/|/Users/)", data, re.IGNORECASE):
        raise ValueError("release binary contains a user directory")
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", "target")))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    target = args.target_dir.resolve()
    environment = os.environ.copy()
    mappings = path_mappings(repo, environment)
    if "CARGO_ENCODED_RUSTFLAGS" in environment:
        flags = [flag for flag in environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f") if flag]
    else:
        flags = environment.get("RUSTFLAGS", "").split()
    flags.extend(f"--remap-path-prefix={source}={replacement}" for source, replacement in mappings)
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    subprocess.run(
        ["cargo", "build", "--workspace", "--all-targets", "--release", "--locked", "--target-dir", str(target)],
        cwd=repo, env=environment, check=True,
    )
    configured_target = environment.get("CARGO_BUILD_TARGET")
    artifact_root = target / configured_target if configured_target else target
    binary = artifact_root / "release" / ("nyra-fw.exe" if os.name == "nt" else "nyra-fw")
    try:
        digest = verify_binary(binary, mappings)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Release artifact check failed. {error}\n")
    print(f"Release CLI path check passed. SHA-256 {digest}")


if __name__ == "__main__":
    main()
