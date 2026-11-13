# NYRA FWLab architecture

```text
nyra-fw-cli
  ├── nyra-fw-core
  ├── nyra-fw-formats
  │     └── nyra-fw-core
  └── nyra-fw-workspace
        ├── nyra-fw-analysis
        │     └── nyra-fw-core
        ├── nyra-fw-formats
        └── nyra-fw-core
```

The CLI controls invocation, resource limits and the Rayon pool. Core provides contracts and shared path rules. Formats validate byte ranges and recover data without filesystem access. Analysis inspects immutable byte slices and parsed records. Workspace orchestrates the stages, invokes isolated tools and publishes results.

The CLI keeps syntax and compatibility tests in `args`, the invocation watchdog and
command routing in `app`, read-only inspection in `scan` and analysis orchestration
in `analyze`. `main` only reports the result. `output` propagates stdout errors,
recognizes a closed stdout pipe specifically and writes diagnostics best effort.
No firmware or workspace I/O error is converted into success by that policy.

## Execution

1. Open a regular input file and read a bounded byte range. Dispatch using format signatures and structural evidence.
2. Recover CRC-verified members or a verified uImage payload. Preserve original input and independent source offsets. Audit central metadata separately for PIHC.
3. Parse ELF headers, dependencies, symbols and selected strings. Report structural failures separately. Stage 03 resolves candidate dependencies and records boot hints. Stage 04 indexes static hardware, module and configuration clues.
4. When explicitly requested, sandbox SquashFS extraction or Ghidra headless analysis. Admit only bounded, validated exports.
5. Generate the typed component inventory, artifact catalog, task plan and authored Claude instructions.
6. Hash the immutable staging tree, cross-check its typed manifests against that inventory and atomically publish it. Later verification and offline resume independently hash the published workspace.

Independent decoders, ELF reports, archive writes and private-stage hashing run on a bounded Rayon pool. The pipeline emits stable record order. The stage inventory reserves file sizes against its aggregate byte budget before hashing. Verification and sandbox artifact admission stream bounded chunks. Optional tool pipes use short-lived readers and process deadlines.

## Module map

`nyra-fw-formats` owns dispatch, format parsers and bounded candidate discovery. Classic ZIP indexes the central directory once and uses it to cross-check bounded local records. PIHC retains a separate local-signature search and shares the ZIP record checks. TAR produces borrowed raw member slices. Both archive readers share portable path collision checks and expose one structural finding used by scan, publication and replay.

`nyra-fw-workspace` is organized by responsibility:

| Module | Responsibility |
| --- | --- |
| `publish` | Dispatch an input, resume, stage in a private sibling, verify and rename atomically. |
| `staging` | Turn a recovered or preserved input into artifacts and evidence (`stage_archive`, `stage_gzip`, `stage_preserved`). |
| `tree` | Write the complete tree for one staged input. |
| `stage02` | Orchestrate the analysis reports and run the later generations. |
| `binary_reports`, `rootfs`, `tools` | ELF index and derived reports, shared bounded RootFS traversal, and the opt-in SquashFS and Ghidra steps. |
| `report_writer`, `output` | Bounded, exclusive, hash-indexed writes. |
| `stage03`, `stage04`, `stage05`, `stage06` | Triage, hardware evidence, handoff and run state. |
| `component_graph`, `byte_map` | Candidate address spaces, artifact links, filesystem observations and original byte coverage. |
| `task_plan`, `guidance`, `agent_index` | Readiness-gated tasks, authored `AGENTS.md` and `CLAUDE.md`, and the machine-readable index. |
| `verify`, `integrity`, `replay`, `golden`, `inspection` | Snapshot, cross-manifest, source-replay and reference checks. |
| `files`, `sandbox`, `ghidra`, `source_map`, `reports` | Bounded reads, the process sandbox, Ghidra export admission and cache, provenance records, summaries. |

## Contracts

New reports must identify their schema and source, retain uncertainty, and participate in workspace verification. Schema tests check generated reports against their contracts. [Workspace schema](workspace-schema.md) · [Security model](security.md)

## Pipeline contracts

PIHC and ZIP converge on format-neutral recovered members, source offsets and typed exclusion reasons. PIHC's directory audit consumes the same index as its decoder. The workspace records exclusions with absolute offsets in `analysis/archive/member-issues.json`. Structure, member verification, ELF coverage and tool outcomes have separate entries in `analysis/workspace/outcomes.json`.

The report writer applies aggregate and individual byte limits while serializing, writes files exclusively and indexes their hashes. The hardware index flows directly from Stage 04 into the handoff. Stage 03 consumes already-validated Ghidra graphs. The typed summary renders the agent documents without reading an intermediate manifest.

The invocation budget combines the input and decoded-byte limits with a 128 MiB weighted admission budget for batches and a 256 MiB budget for generated analysis reports. ELF admission uses a conservative size estimate. The CLI deadline covers file I/O, and analysis checks the remaining time before publication and external work.

RootFS enumeration uses directory handles, rejects links and applies the invocation
entry and deadline limits while collecting directory entries. ELF indexing, extraction
indexing and Stage 04 share that implementation. Prefix admission and ELF reads use
one checked file handle. Stage 04 hashes the same bytes used for configuration and
module observations. [Safety contracts and regression checks](security.md#safety-contracts)

One per-publication RootFS inventory now owns the admitted sorted paths and
fingerprints consumed by ELF, checksum and hardware indexing. Successful ELF
inspection contributes its existing SHA-256; later indexing reuses it. Configuration
and module reads still hash their admitted bytes and reject conflicts with earlier
observations. Unrelated Stage 04 paths need no second open. The cache never survives
a run, and final publication independently hashes and reconciles the staging tree.

`core::source` binds checked ranges to their borrowed bytes and coordinate identity.
An original-input candidate range rejects decoded candidates; decoded ranges require
the matching gzip parent ID. An identity describes caller-established provenance,
not authentication. These views are runtime contracts, not deserializable claims.
Public offset fields remain compatible DTOs and are checked when admitted. Internal
filesystem and recovery enums retain the existing serialized labels; unknown recovery
states fail deserialization.

## Memory model

The input is read into memory once, up to 512 MiB. Readers borrow ranges for random access, so a TAR member can be written directly from the source buffer. ZIP and PIHC hold recovered member bytes under the 256 MiB decoded-output budget. Temporary decoder batches and report buffers have separate bounds. Verification reads files in chunks. Resident memory depends on the format, the volume of recovered bytes and the active analysis phases.

## Reuse and failure isolation

`--resume` reuses a completed offline workspace after verifying its snapshot and matching its input and policy. The release version scopes the key. Older workspaces can still be checked with `verify`.

Ghidra export reuse is opt-in with `--ghidra-cache DIR` and requires an explicit `NYRA_JAVA_HOME`. Use an existing private directory and trusted immutable Ghidra and JDK installations. The key binds the ELF SHA-256, target path, NYRA release, architecture, installed Ghidra bytes, JDK runtime bytes under `bin/`, `conf/` and `lib/`, embedded scripts and analysis settings. A hit checks all export digests and parses each export again. Writes use a staged no-replace rename. The v2 namespace serializes publication and eviction with an OS file lock. It has a 512 MiB content budget and a 64-entry cap. Interrupted writes and oldest entries are reclaimed when needed. Bad entries are bypassed and can be replaced by newly validated output. Symlinked toolchain layouts can run uncached. The cache reports hits, misses and bypass reasons on standard error.

With `--allow-partial-tools`, completed tools contribute validated products. Failed tools record a category and fixed portable diagnostic. The run deadline and publication failures still abort the operation. `--allow-partial` independently governs firmware recovery.

Ghidra export admission lives in the analysis crate, shared by fresh tool output
and workspace cache reads. Each JSON input is limited to 64 MiB, the bundle to
128 MiB. A bounded deserializer rejects an excess list item before decoding its
payload: 20,000 functions, 30,000 edges and 120 decompilation entries. Functions
have unique nonempty entry identities; names may collide. Pseudocode with a failed
decompilation status is rejected. A bundle cross-checks known entry/name identities
and references against a complete function index. At the legacy exporter's
20,000-function boundary, absence remains unproven. These consistency checks do
not establish binary authenticity or correctness of Ghidra's inferred results.

## Source replay

`verify --replay` first verifies the immutable workspace. It reads and hashes the source again, repeats PIHC, ZIP, TAR, uImage or gzip processing, and compares the entire artifact set including transformations, byte ranges and SHA-256. It uses the recorded supported PIHC transform variant, or probes when the manifest has no variant. The snapshot continues to cover external tool outputs. Independent fixture comparisons exercise the decoder with an external byte reference.

Preserved-input replay re-derives the candidate report and applies the recorded selection when present. `verify --agent-ready` checks the canonical agent handoff and rejects unexpected root entries. It can be combined with replay. [Agent workflow](agent-workflow.md)

## Release artifacts

CI builds the locked release twice in separate target directories and compares the CLI binaries byte for byte on each host. The MSVC release links with a deterministic PE timestamp and records the PDB filename without its build directory. [Microsoft linker option](https://learn.microsoft.com/en-us/cpp/build/reference/pdbaltpath-use-alternate-pdb-path)

Use `python -B scripts/build-release.py --target-dir target` to build a distributable native executable. The script passes source-path remappings through Cargo to the workspace and its dependencies, then checks the CLI for local build prefixes in UTF-8 and UTF-16. CI uses this command for both release builds and runs smoke tests directly against the checked binary. Debug symbols such as PDB files can retain linker-generated paths. Publish the checked CLI executable and keep the remaining build directory private. [Rust compiler path remapping](https://doc.rust-lang.org/rustc/remap-source-paths.html)

## Development checks

Use the pinned toolchain and lockfiles. Run these checks before publishing code:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python -B -m unittest discover -s tests -p "test_*.py"
cargo doc --workspace --no-deps --locked
python -B scripts/build-release.py
```

Set `RUSTDOCFLAGS="-D warnings"` for the documentation build, using your shell's
syntax for environment variables. Parser changes also need the matching bounded
[fuzz target](../fuzz/README.md). Report changes must update their schema in
`schemas/` and remain covered by the generated-report checks. Firmware, logs and
decompiler output stay data; no test may execute recovered code or flash a device.

## Binary release packaging

Official targets are `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-gnu`.
The native MSVC release helper links the C runtime statically. Build twice in
separate target directories before packaging a clean committed source tree:

```bash
python -B scripts/package-release.py --binary /path/to/nyra-fw --output /path/outside/checkout
```

Archives contain the executable, MIT license, standalone instructions and build
identity. Fixed timestamps, ordering, ownership and permissions make packaging
repeatable. The index mode verifies both platform archives and emits
`release-manifest.json` and `SHA256SUMS`. Its contract is
[release-artifacts.schema.json](../schemas/release-artifacts.schema.json). Linux
GNU runtime requirements must be checked on the actual binary before publication.
