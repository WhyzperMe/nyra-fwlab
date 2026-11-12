# NYRA FWLab

NYRA FWLab 0.10.1 is an offline firmware recovery, static reverse-engineering and Claude-workspace tool. Build with Rust 1.95.0 and the checked-in lockfile. Windows and Linux are covered by the release checks. Optional external analysis runs in a Linux sandbox, including WSL2 hosts that permit unprivileged user namespaces.

| Input | What the pipeline establishes |
| --- | --- |
| HiChip PIHC | Header bounds, raw carves and individually CRC-verified ZIP members. ZIP directory consistency is reported separately. |
| Classic ZIP | Consistent central and local records, including streamed data descriptors. Portable paths, exact stored or DEFLATE output and CRC per member. |
| USTAR / GNU TAR subset | Checksummed headers and bounded regular file ranges. Raw members have source SHA-256 provenance and are stored separately from CRC-verified recovery. |
| SquashFS 4.0 | Superblock and table bounds. Optional extraction inventories regular files and stores links as metadata. |
| ELF | Bounded parsing of headers, dependencies, symbols and addressable strings. |
| Single-member gzip | Bounded decompression with CRC and ISIZE validation. The payload enters static ELF or optional SquashFS analysis when recognized. |
| Legacy U-Boot uImage | CRC-verified payload carve, sizes, load and entry addresses and numeric type metadata. |
| Unknown or corrupt input | Strict by default. With `--allow-partial` the source is preserved, a bounded scan lists embedded structure candidates with their failed or passed checks, conflicts and derived next steps, and validated non-overlapping structures are carved with exact source ranges. See [candidate discovery](docs/candidates.md). |

The pipeline never runs extracted firmware or writes to a device. Individual byte checks establish no vendor identity, hardware behavior, complete flash image or flashability.

## License

Copyright (c) 2026 Whyzper.Me ([GitHub](https://github.com/WhyzperMe)), licensed under the [MIT License](LICENSE). You may use, modify and redistribute the code, including commercially, if you keep the copyright notice and the license text. The licenses cover this repository only. They grant no rights to any firmware you analyze, and the format constants noted in [SECURITY.md](SECURITY.md) come from a vendor update package. Dependencies keep their own licenses.

## Build and use

```bash
cargo build --workspace --release --locked
cargo run --release --locked -p nyra-fw-cli -- scan firmware.pkg --json
cargo run --release --locked -p nyra-fw-cli -- analyze firmware.pkg --profile auto --threads 8 --workspace workspaces/camera
cargo run --release --locked -p nyra-fw-cli -- analyze firmware.pkg --workspace workspaces/profile --timings --json
cargo run --release --locked -p nyra-fw-cli -- scan unknown.bin --json
cargo run --release --locked -p nyra-fw-cli -- analyze unknown.bin --workspace workspaces/unknown --allow-partial
cargo run --release --locked -p nyra-fw-cli -- analyze unknown.bin --workspace workspaces/selected --allow-partial --candidate 0
cargo run --release --locked -p nyra-fw-cli -- inspect workspaces/camera
cargo run --release --locked -p nyra-fw-cli -- verify workspaces/camera --replay --agent-ready --json
cargo run --release --locked -p nyra-fw-cli -- export-agent workspaces/camera --output workspaces/camera-agent
cargo run --release --locked -p nyra-fw-cli -- verify-agent-export workspaces/camera-agent
cargo run --release --locked -p nyra-fw-cli -- analyze firmware.pkg --workspace workspaces/camera --resume
```

The workspace destination must be fresh, except when `--resume` verifies a completed offline run against the input bytes, source filename, release version and recovery options. Choose a destination parent that you control. On WSL2, use a native Linux output directory such as `~/workspaces`. WSL2 Windows mounts can reject the atomic directory rename required for publication. Use `--run-timeout-seconds` to set the CLI wall-clock deadline. [Security model](docs/security.md)

For a distributable native executable, use `python -B scripts/build-release.py`. It remaps local source and dependency paths and checks the resulting CLI for user-directory references. Publish the checked `target/release/nyra-fw` executable (`nyra-fw.exe` on Windows). Keep compiler caches and PDB files private. [Release build details](docs/architecture.md#release-artifacts)

### External tools on Linux

Install bubblewrap, util-linux, GNU tar, awk and squashfs-tools using trusted system packages. Ghidra also requires a trusted installation and a compatible Linux JDK. Set `NYRA_JAVA_HOME` for a JDK installed outside the system paths.

Ghidra 12.2 with Linux Temurin JDK 25.0.5 has passed local live qualification on a
reference ELF and the SSC338Q ARM target, including exports, cache reuse and replay.
[Tested scope](VALIDATION.md#live-ghidra-qualification--2026-11-12) · [Repeat the gate](docs/corpus.md#security-gates)

```bash
nyra-fw analyze firmware.pkg --workspace workspaces/camera-rootfs --extract-filesystems
NYRA_JAVA_HOME=/opt/jdk-25 nyra-fw analyze firmware.pkg --workspace workspaces/camera-ghidra --ghidra-headless /opt/ghidra/support/analyzeHeadless
nyra-fw verify workspaces/camera --golden /path/to/recovery_manifest.json
```

External tool failures abort publication by default. Use `--allow-partial-tools` to publish verified recovery with the tool failure recorded in `analysis/workspace/outcomes.json`. To reuse validated Ghidra exports, pass `--ghidra-cache` with an existing private directory separate from the workspace and set `NYRA_JAVA_HOME`. Add `--require-cgroup` to require a delegated Linux process-tree limit before launching a tool. See [the architecture notes](docs/architecture.md) for the cache contract.

## Workspace

Before opening a generated workspace in an agent, run `nyra-fw verify <workspace> --agent-ready` with a trusted local binary. Start with `AGENTS.md` (identical to `CLAUDE.md`), then use `analysis/workspace/agent-index.json` to find the relevant evidence. The source copy is under `original/`. Recovered files and raw carves are under `recovered/`. Use `reconstruction/` for editable work. [Agent workflow](docs/agent-workflow.md)

The component graph links candidate IDs, address spaces and materialized artifacts. For standalone ZIP and USTAR, `scan --json` and the workspace expose the same structural finding, including declared ZIP CRCs. Source replay reconstructs both reports from the source. [Report contracts](docs/workspace-schema.md)

See the [documentation index](docs/README.md), [architecture](docs/architecture.md), [candidate discovery](docs/candidates.md) and [validation results](VALIDATION.md).

Run the independent candidate corpus to measure recognition coverage and compare releases on the same host. [Corpus and performance checks](docs/corpus.md)
