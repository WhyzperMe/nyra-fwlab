# Release validation

## Live Ghidra qualification — 2026-11-12

The local live-Ghidra gate previously marked **NOT VERIFIED** is now **PASS** for
the P2 Linux CLI (SHA-256
`980f8558aee3bcdb26de9fc1de93fc2bcd97646fb4814ec2ba838b9a44278e55`),
Ghidra 12.2 and Eclipse Temurin Linux x64 JDK 25.0.5+8 under WSL. The operator's
Ghidra installation was used through its Linux `support/analyzeHeadless` entry.
The system Java default was not changed.

The standalone JDK archive came from the official
[Temurin release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8).
Its SHA-256 matched both the published checksum file and the release API asset
digest: `68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb`.
The archive and toolchain remain outside the repository. This records download
integrity, not a signature verification.

The strengthened `scripts/check-ghidra-gate.sh` passed:

- Two fresh analyses of one independently compiled reference ELF produced identical provenance and all three exports.
- The expected function and its static call from `main` were present; the known lens function produced successful nonempty inferred pseudocode.
- Pinned Ghidra/Java versions and the exact target ELF SHA-256 matched provenance.
- A real cache miss followed by a hit was observed. Cached exports matched the fresh exports; cached provenance matched across the pair and included Ghidra/JDK fingerprints.
- All four workspaces passed replay and agent-ready verification.
- Timeout, forced interruption, process-tree cleanup and delegated-cgroup memory-pressure gates passed.

A separate live run on the verified SSC338Q ARM32 little-endian `ipc_server`
exported 2,914 functions, 20,914 static entry references and 120 nonempty inferred
pseudocode results. The Ghidra phase took 87.3 s (88.0 s total invocation), within
the explicitly selected 600 s tool budget. The 120 results are the exporter's
capped lens-related selection, not decompilation of every function. The resulting
workspace passed replay of 495 artifacts, canonical agent verification and all
493 golden filename/SHA-256 comparisons. No imported firmware or reference ELF
was executed or flashed.

This qualifies the tested adapter, exporter and cache paths for this version pair
and these x86-64/ARM examples. It does not prove decompiler correctness, complete
firmware reconstruction or support for every architecture. Repeat qualification
when the CLI, exporters, Ghidra or JDK change. [Reproduction commands](docs/corpus.md#security-gates)

**Hosted CI:** check the [main-branch workflow runs](https://github.com/WhyzperMe/nyra-fwlab/actions/workflows/ci.yml?query=branch%3Amain)
for the tested commit and conclusion. The first hosted run passed Ubuntu verification,
the independent corpus, dependency audits and fuzzing, but exposed a Windows test
stub comparing resolved and unresolved temporary paths. A portable path-alias
regression reproduced that failure locally; using actual file identity fixes it.
The updated 16-test Python suite passed locally on Windows and Linux. Earlier
sections retain their historical qualification status and are superseded here
only for the local live-Ghidra gate; a hosted run is qualified only when it finishes
successfully for the target commit.

## P2 architecture and export admission — 2026-11-12

P2 separates CLI responsibilities, hardens Ghidra export admission and makes
performance comparisons fail on different source/artifact identities. It adds no
dependencies or runtime. Public Rust export DTO fields, JSON labels and schema
versions remain unchanged. Inconsistent export data is now refused more strictly.

Two new negative tests failed before the fix: duplicate function entry identities
and nonempty pseudocode marked as a failed decompilation were accepted. The
preserved P1 Linux CLI also reproduced a closed-stdout panic (exit 101). Regression
tests now cover these cases, early collection/byte limits, bundle consistency,
ambiguous names, the capped function index and rehashed inconsistent cache entries.
The stdout policy preserves errors from unrelated firmware/workspace I/O.

**Build gates:** final Linux formatting, locked all-target check, Clippy with
warnings denied, all 143 Rust tests, rustdoc with warnings denied and the remapped
all-target release build passed. Two final Linux CLI builds in separate target
directories are byte-identical, SHA-256
`980f8558aee3bcdb26de9fc1de93fc2bcd97646fb4814ec2ba838b9a44278e55`.
Windows formatting, check, Clippy, rustdoc and builds passed; 141 Rust tests are
covered by the full run and targeted checks after the final small changes. Both
final Windows release CLIs match, SHA-256
`7ac2f600a3c18e2a9d051619646a029aafae588e2c9148b235cb5be46f6fa8c9`.
All 16 Python tests, both RustSec lockfile audits and ShellCheck passed. The Windows
release CLI also passed synthetic PIHC recovery, golden comparison, replay and
agent-ready verification using the legacy `recover`/`--output` aliases.

**Compatibility:** fresh SSC338Q runs with one and eight workers matched all 493
reference filenames and SHA-256 values and replayed all 495 artifacts. Entire
workspaces match a fresh P1 run byte for byte. WRX36 with sandboxed extraction is
also byte-identical to P1 and passes replay/agent-ready. Scan JSON matched P1 on
six representative fixtures, with and without candidate discovery. Help text
matched with the same executable name. Resume, verified inspection, detached agent
export and the new closed-pipe behavior passed. New malformed-option checks fail
before input I/O; `--ghidra-target` now requires `--ghidra-headless` in Clap as well
as the existing library validation.

**Security gates:** the 54 generated independent corpus cases and three pinned
Raspberry Pi references passed scanner comparisons. SquashFS admission and Linux
failure gates passed, including timeout, interruption, process-tree cleanup and
delegated-cgroup memory pressure. The expanded Ghidra export target completed
1,089,136 AddressSanitizer fuzz executions in 61 seconds without a failure. Other
unchanged fuzz targets were not rerun for P2.

**Performance:** eight workers, alternating binaries, a discarded warmup and 15
fresh-workspace samples per binary on the same host, after builds and fuzzing had
finished. Every source/artifact identity matched; the comparison now fails on the
first disagreement. [Raw measurements](docs/benchmarks/p2-comparison.json)

| Workload | P1 median | P2 median | P1 / P2 maximum peak RSS |
| --- | ---: | ---: | ---: |
| 512 small ZIP members | 0.346 s | 0.341 s | 7.15 / 6.96 MiB |
| 128 MiB sparse input | 0.468 s | 0.442 s | 133.55 / 133.65 MiB |
| Overlapping invalid uImage CRC claims | 0.228 s | 0.231 s | 37.82 / 37.77 MiB |
| SSC338Q | 0.654 s | 0.685 s | 84.71 / 84.30 MiB |

No overall speedup is established. The initial five-sample comparison ranged from
2.9% faster to 8.4% slower; the extended run ranges from 5.7% faster to 4.8% slower.
SSC338Q was 4.1% slower initially and 4.8% slower in the extended comparison, so a
separate six-sample, alternating `--timings` profile investigated that observation.
Its process medians were 0.755 / 0.756 s; staging medians were 0.343 / 0.355 s
and analysis medians 0.260 / 0.241 s. This does not erase the observed slowdown or establish its
cause; storage/host variation is not fully controlled and further performance
qualification needs a dedicated host. [Initial measurements](docs/benchmarks/p2-initial-comparison.json)
and [phase profile](docs/benchmarks/p2-phase-profile.json) retain both observations.

**NOT VERIFIED:** live Ghidra execution with these stricter export checks (the
checked Linux JDK is 21; Ghidra 12.2 requires a trusted Linux JDK 25 or newer), and
hosted GitHub CI (no configured remote). Synthetic exporter/cache tests do not
replace live integration. P2 is locally validated, not a full external release
qualification or a guarantee of reconstructing arbitrary firmware formats.

## P1 architecture qualification — 2026-11-12

The Unreleased tree adds source-bound checked ranges, internal filesystem/recovery
enums and one per-publication RootFS inventory. Public manifest fields, schema
versions and serialized labels are unchanged. The inventory caches fingerprints,
not file contents; configuration/module reads reject contradictory observations,
and the independent final disk snapshot remains mandatory.

**Executed on the final Linux tree:** formatting, locked all-target check, Clippy
with warnings denied, all 129 Rust tests, rustdoc with warnings denied and the
locked all-target release build passed. The two remapped native release builds
are byte-identical (SHA-256
`0fbe8fc26fe4cae3294b75384fba52d120200b029943f584df3bdef12d0c3b0f`).
Both RustSec lockfile audits, 11 Python tests and ShellCheck passed. The SquashFS
sandbox gate and Linux failure gates passed, including timeout, interruption,
process-tree cleanup and memory pressure in a delegated systemd cgroup. A direct
probe of the root cgroup was not sufficient to determine delegation availability.

On Windows, workspace and fuzz formatting, locked Clippy, all 127 Rust tests and
11 Python tests passed. Two final remapped all-target release builds are
byte-identical (CLI SHA-256
`9c72988c2177889d3062055c768b9eaab80477f34a81c1eda9fba59d6c97ea88`).

Final SSC338Q runs with one and eight workers matched all 493 reference names and
SHA-256 values, re-derived 495 artifacts and passed agent-ready verification.
Both entire workspaces are byte-identical to a fresh run of the preserved P0
binary. WRX36 extraction and replay also passed, with its entire workspace
byte-identical to P0. The new verifier accepts both P0 workspaces without migration.

**Performance:** the final native Linux binaries were alternated on the same host,
with eight workers, one discarded warmup and 15 fresh-workspace samples per binary
and workload. Builds and fuzzing had finished before this run. All source-artifact
identities matched. The first five-sample run overlapped builds/fuzzing and is not
used to infer performance. [Final raw measurements](docs/benchmarks/p1-comparison.json)

| Workload | P0 median | P1 median | P0 / P1 maximum peak RSS |
| --- | ---: | ---: | ---: |
| 512 small ZIP members | 0.699 s | 0.713 s | 7.02 / 6.98 MiB |
| 128 MiB sparse input | 1.047 s | 1.068 s | 133.78 / 133.73 MiB |
| Overlapping invalid uImage CRC claims | 0.485 s | 0.472 s | 37.84 / 37.69 MiB |
| WRX36 with sandboxed extraction | 5.585 s | 5.643 s | 33.33 / 33.17 MiB |

These measurements establish no overall speedup: median differences range from
2.7% faster to 2.0% slower, and host/storage variation is not fully controlled.
The structural reduction is three RootFS enumerations to one, reuse of successful
ELF hashes and fewer unrelated Stage 04 opens. Independent final hashing and
durable publication remain in the measured path.

The 54 independently generated corpus cases passed. Three official Raspberry Pi
boot files from commit `12eeaa12865869b07db760f4bbb7507ec6f1976c` were retrieved
outside the repository and matched the new pinned reference manifest. ELF layout
was independently checked with `readelf`; FDT with `dtc`/`fdtget`. All three passed
candidate comparisons, partial publication, replay and agent-ready verification.
The opaque bootcode remains partial; no complete board recovery is claimed. The
reference hashes pin retrieved bytes and are not publisher signatures.

The candidate fuzz target, extended with checked-range assertions, completed
52,402 AddressSanitizer executions in 61 seconds without a failure. Other fuzz
targets were not rerun for this change. The nightly toolchain lacks rustfmt, so
the fuzz crate was formatted and checked using the pinned stable toolchain.

**NOT VERIFIED:** hosted GitHub CI (no Git remote configured) and live Ghidra
analysis (the checked Linux environment has JDK 21; Ghidra 12.2 requires a trusted
Linux JDK 25 or newer). The scheduled Raspberry Pi download/replay job is prepared
but has not run on GitHub. The project is not declared fully release-qualified
while these external gates remain open. Unknown proprietary formats can still
require new decoders; partial preservation is not complete reconstruction.

## P0 safety qualification — 2026-11-12

The current Unreleased tree establishes the [P0 safety contracts](docs/p0-contracts.md).
The pre-change baseline passed all 118 Rust tests. Two new negative tests then
reproduced a followed replacement RootFS link and a publication callback invoked
after its budget had already expired. Both tests pass with the fixes.

- RootFS enumeration now opens ancestors and child directories through no-follow handles and checks the invocation's entry, path and deadline limits before collecting directory contents. ELF, extraction and hardware indexing share this implementation.
- Extracted ELF prefix checks and full reads retain one checked handle. Stage 04 configuration and module observations use bounded reads and hash the admitted bytes. Stage 04 receives the invocation budget instead of using default limits.
- Publication checks its budget before filesystem work and before invoking its writer. Destination names are validated before parent creation and path normalization. Regression tests cover expired budgets, invalid names, changed file sizes, replaced paths and traversal limits.
- Windows passed formatting, locked all-target check, Clippy with warnings denied, 123 Rust tests, rustdoc and the locked release build. Linux passed the same gates with 125 Rust tests, including two Unix-specific link/handle tests. All ten Python tests passed on both hosts.
- Sanitized release builds passed the path audit and were byte-identical across two target directories on each host. Seven Windows release CLI cases covered PIHC, four ZIP variants, TAR and gzip, with golden comparisons, source replay and detached agent export.
- SSC338Q automatic-profile recovery matched all 493 golden filenames and SHA-256 values with one and eight workers. Replay verified 495 artifacts, both immutable inventories matched, and detached agent export verified.
- Real WRX36 extraction, hardware analysis and replay passed. The resulting RootFS retained 24,369,968 regular bytes and 238 symlink targets as metadata, with 186 ELF objects analyzed. The SquashFS policy gate and synthetic timeout, forced interruption/retry, process cleanup and delegated cgroup memory gates passed.
- Both RustSec lockfile audits passed. Report schemas and public CLI arguments retain their current contracts.

**NOT VERIFIED** — hosted GitHub Actions and live Ghidra decompilation. The latter
requires a configured trusted installation and compatible Linux JDK. Firmware
completeness, physical hardware behavior and flashability remain outside these checks.

## Working-tree audit — 2026-11-11

The current 0.10.1 source tree includes the fixes listed under Unreleased in the changelog.

- A regression test reproduced acceptance of a SquashFS root-inode pointer into a metadata block. The fixed reader requires the referenced block header to occur in the inode-table chain and checks offsets against the stored size for uncompressed blocks.
- Windows and WSL Ubuntu 24.04 passed formatting, locked all-target checks, Clippy with warnings denied, all 118 Rust tests and the locked release build. Windows rustdoc also passed with warnings denied.
- All ten Python regression tests passed on both hosts. They cover owned temporary files, failed downloads, selected manifests, cache and timeout bounds, and release artifact path checks. A live publisher download matched the pinned OpenWrt digest, produced a one-case manifest and passed cached reuse.
- The 54 generated unseen-family corpus cases passed. Preserved truncated SquashFS, CRC-damaged gzip and CRC-damaged ZIP inputs published and replayed.
- A fresh SSC338Q analysis matched all 493 golden filenames and SHA-256 values. Replay independently verified 495 artifacts, and the agent-ready check passed.
- AddressSanitizer runs completed without a crash or timeout. SquashFS ran 61 seconds and 941,155 executions; candidate discovery ran 61 seconds and 94,613 executions.
- Both RustSec lockfile audits passed.
- The native release build helper remapped local source paths and passed the artifact privacy scan. On each host, builds in two external target directories produced byte-identical CLI binaries. The Windows CLI SHA-256 was `eac8681b9320c1fccff0830e7598bccde7a9bd0f32dd359fa66e9862d953d071`.
- Git is initialized locally on `main` with Whyzper.Me as the project author. A source-tree Git archive preserved all 40 binary fixtures and fuzz seeds byte for byte and contained no compiler caches, environment files or Git metadata. All shell scripts passed ShellCheck, and both workflow files parsed as valid YAML. GitHub Action pins were verified against their upstream repositories.

**NOT VERIFIED** — hosted GitHub Actions and repository-side settings, which require a configured remote repository; live Ghidra integration, which requires a configured trusted installation and compatible Linux JDK. No remote is configured and no initial commit has been created. The source changes remain available for review. Historical release results below retain their original scope.

## 0.10.1 unseen-family corpus, archive classification and SquashFS tables

All results come from one WSL2 host (kernel 6.18.33.2, Ubuntu, Rust 1.95.0) with the repository on DrvFs and every build and workspace on native ext4. The independent references were `mksquashfs`/`unsquashfs` 4.6.1, `mkimage` 2025.10, DTC 1.7.0, mtd-utils 2.2.0, Info-ZIP `zip` 3.0, GNU tar 1.35, xz 5.4.5 and Python 3.12.3 (`zlib`, `zipfile`, `gzip`, `lzma`).

**Corpus.** Eleven real OpenWrt 25.12.6 images from six SoC families that no earlier reference covered (Broadcom bcm53xx, Realtek rtl838x, Marvell mvebu, Lantiq xrx200, MediaTek Filogic and Qualcomm IPQ40xx) were fetched from the publisher and matched its published SHA-256 list. The manifest pins their digests and 338 independently annotated ranges. [Manifest](tests/fixtures/reference/openwrt-unseen-25.12.6.json) A generated corpus of 54 cases adds valid, truncated, bit-flipped and overlapping variants: all six SquashFS compressors, uImage, FIT with embedded and external data, UBI, JFFS2, and ZIP, gzip and xz variants. The generator states every expectation by construction, and an independent oracle (no NYRA code) must agree before a case is written. It agreed on all 54 cases, with 65 expected ranges. Firmware stays outside the repository.

| Build | Real images | Real ranges | Generated cases | Generated ranges |
| --- | ---: | ---: | ---: | ---: |
| 0.10.0 | 9 of 11 pass | 206 matched, 132 missing, 2 false | 48 of 54 pass | 59 matched, 6 missing |
| 0.10.1 | 11 of 11 pass | 338 matched, 0 missing, 0 false | 54 of 54 pass | 65 matched, 0 missing |

Every matched range agrees on offset, extent, range SHA-256 and evidence tier. No budget was exhausted. The disagreements with 0.10.0 were reproduced, traced and fixed:

- **False SquashFS carve.** Two UBI-based images (`8dev_jalapeno`, `alfa-network_ap120c-ac`) contained a SquashFS whose superblock was valid but whose metadata tables were interleaved with erase-block headers. 0.10.0 reported it as validated and carvable, and extraction failed with "File system corruption detected". `unsquashfs -stat` accepts it, `unsquashfs -ll` does not. 0.10.1 follows the inode and directory block chains and the fragment, export and id tables with their indexes, and rejects it. The same check catches an image whose tail is damaged. The 80 xz block streams in each image are no longer explained by a filesystem and are listed individually.
- **Invisible ZIPs.** ZIPs with a bzip2 or LZMA member, a non-ASCII, unsafe or repeated name and a ZIP stored inside a ZIP member were not found. Structure is now judged apart from the extraction policy. ZIP64 stays outside the subset and is rejected under its own check.
- **Misleading classification.** A valid GNU TAR with repeated member names (the CTERA C200 v2 wrapper) and archives outside the ZIP subset were reported as `structure_check_failed`. They are now `unsupported`.
- **Abort under `--allow-partial`.** A valid gzip beyond the 32 MiB member limit (the OpenWrt x86 `.img.gz`) made `analyze --allow-partial` fail, while `scan` reported a budget. It is now preserved with its candidate report. A mutation of the fix makes the new regression test fail.

Oracle defects were found the same way, by disagreement with NYRA, and fixed before the references were recorded: gzip extent accounting across read blocks, the use of `unsquashfs -stat` where `-ll` is required, `zipfile` choosing a forged end record from a comment, ignoring the disk fields, overlong central entries and data descriptor values, and `dtc` accepting header values that libfdt refuses. The OpenWrt x86 `.img.gz` is not in the manifest. Its decoded image exceeds the member limit, so a scan reports the exhausted budget instead of a result.

**Pipeline.** All 65 inputs (54 generated, 11 real) published workspaces with `--allow-partial`, passed `verify --replay --agent-ready` and produced a verifiable agent export. Every carvable candidate was then selected and carved on its own, with sandboxed `--extract-filesystems` for SquashFS, and replayed: no failure. Without `--allow-partial`, 51 of the 66 inputs (these 65 and the x86 image) were refused and 15 were published. No refusal left a workspace or a staging directory behind, and no input caused a panic.

**Release gates.** `cargo fmt --check`, locked all-target check, Clippy with warnings denied and rustdoc with warnings denied passed. All 117 workspace tests passed (103 in 0.10.0). The locked release build was byte-identical when built twice in different target directories (SHA-256 `88e6bdf22283...`). Both RustSec lockfile audits passed. The CI synthetic smoke gates passed locally: PIHC, four ZIP variants, TAR, gzip, embedded candidate selection, the legacy six-case corpus and agent export. The SquashFS sandbox gate and the Linux failure gates (timeout, forced interruption, process-tree cleanup, cgroup memory) passed.

**SSC338Q golden.** 0.10.0 and 0.10.1 both recovered all 493 members with one and eight workers. All 493 filenames and SHA-256 values matched the phase-01 manifest, and replay re-derived 495 artifacts. The 1 and 8 worker workspaces are byte-identical. Against 0.10.0, `original/`, `recovered/` and every other report are identical. Only the version-bearing manifests differ, through the producer string, the cache key and hashes derived from them.

**Compatibility.** Under 0.10.1, the 0.10.0 workspaces of nine of the eleven real images and both SSC338Q workspaces still pass replay. The two UBI-based workspaces do not: their stored report names the SquashFS carve above. Replay reports a candidate report mismatch and the workspace has to be regenerated.

**Differential fuzzing.** `scripts/oracle-fuzz.py` mutated the generated seeds 100,000 times and structures cut from the real images 30,000 times. Each mutant was scanned by 0.10.1 and annotated by the independent oracle. 129,199 agreed on kind, offset, extent and tier. 801 differed for a reason that the script decided with its own check: 737 DTB rules that `dtc` and libfdt do not enforce (zero padding, unnamed root, `FDT_END` ending the block, reservation terminator, versions 16 and 17), 50 SquashFS metadata blocks that the scanner does not decompress, 42 xz streams that follow from the SquashFS cases, 10 root inode references with ignored upper bits, 3 ZIP `version needed` values and 1 corrupt extra field that the scanner does not parse. None was unexplained, and the scanner never failed. Earlier batches found and led to three fixes: the tail-table check, a stricter oracle for ZIP and FDT, and the class definitions above.

**Fuzzing.** All nine targets ran under AddressSanitizer with copied corpora: 10,605,038 executions without a crash, timeout, out-of-memory or assertion failure. Candidates and ZIP ran 75 s, SquashFS and TAR 45 s, the other five 20 s. The ZIP target asserts that every archive recovery accepts passes the structure check, and the candidate target asserts strict, validated containment.

**Performance and memory.** The repository harness alternated 0.10.0 and 0.10.1 on identical inputs with eight workers, one warmup and 15 timed fresh workspaces per binary. Artifact paths, digests and source ranges were identical in all four workloads. Run-to-run variation on this host was large: two earlier five-run measurements put the medians between 23 % faster and 53 % slower, with changing sign per workload. The table shows the last of three 15-run measurements, taken on a quiet host with the final binary. Its medians differ by at most 1.2 %. The first two 15-run measurements, with host load, differed by at most 8 %, again with changing sign.

| Workload | 0.10.0 median | 0.10.1 median | 0.10.0 / 0.10.1 peak RSS |
| --- | ---: | ---: | ---: |
| 512 small ZIP members | 0.271 s | 0.272 s | 6.8 / 6.9 MiB |
| 128 MiB sparse input | 0.401 s | 0.401 s | 133.7 / 133.7 MiB |
| Overlapping invalid uImage CRC claims | 0.205 s | 0.207 s | 37.9 / 37.7 MiB |
| SSC338Q | 0.595 s | 0.602 s | 84.3 / 84.7 MiB |

Candidate scans of the eleven real images took 10 to 70 ms each in both builds, with a maximum peak RSS of 30.8 MiB in both. A hostile 190 MiB input with 512 valid-looking SquashFS superblocks and maximum-length chains took 0.36 to 0.49 s in 0.10.0 and 0.41 to 0.83 s in 0.10.1, with the same peak RSS of about 197 MiB. The walks are bounded at 65,536 blocks per table and 512 validation attempts.

**NOT VERIFIED:**

- **Ghidra for 0.10.1.** The operator-provided Ghidra 12.2 installation is byte-identical to the official archive, whose SHA-256 matched the release notes (`2c2cd776...a7be67`; the release carries no signature). The repository's gate started it under 0.10.1 and Ghidra refused to run: 12.2 requires JDK 25 or newer, and the Linux host has only OpenJDK 21.0.12.1 (the JDK 25.0.2 under Windows cannot run in the Linux sandbox). A Linux Temurin 25.0.5+8 was downloaded and matched both published digests, but running a downloaded JDK was blocked by the host's permission policy. Runtime, peak RSS and artifact identity of the Ghidra phases were therefore not compared with 0.10.0. The gate needs `NYRA_JAVA_HOME` to point to a Linux JDK 25 or newer that the operator trusts.
- Hosted CI execution, including the new `unseen-corpus` job, and any Windows run of this release.
- The 60-second scheduled fuzz budget, and any fuzzing beyond the durations above.
- Hardware flashing and support beyond the format subset. Findings establish annotated byte ranges and replayed artifacts only.

**Known limits that the corpus exposed and this release does not change.** ZIP64 and archives whose offsets Info-ZIP `-A` rewrote relative to a prefix are not recognized as ZIP structures. UBI images are reported as one erase-counter candidate per erase block (78 and 79 in the two real images) with no extent. xz, bzip2 and zstd findings remain header-only, and no parser was added: the real fixtures show no need that the existing candidate tiers do not already cover.

## 0.10.0 archive evidence and workspace hardening

- Windows and WSL2 passed formatting, locked all-target checks, Clippy with warnings denied, all 103 workspace tests and the locked release build. Windows also passed rustdoc with warnings denied. On each host, two builds in different target directories produced byte-identical CLI binaries.
- The Windows release verified and replayed classic ZIP and PIHC workspaces generated with 0.9.0. The synthetic PIHC golden hashes also matched.
- Python's independent readers agreed with all regular member offsets, lengths and declared ZIP CRCs across four classic ZIP variants and one USTAR. Golden ZIP payload checks and USTAR raw member comparison passed. A corrupt ZIP payload test preserved the structural finding while correctly reporting failed CRC verification.
- The synthetic candidate corpus matched seven annotated ranges across six cases. The three pinned OpenWrt images matched all nine annotated ranges, and all three passed workspace publication, source replay and detached agent export.
- WSL2 SSC338Q automatic-profile recovery verified all 493 eligible members with both one and eight workers. All 493 filenames and SHA-256 values matched the phase-01 golden manifest. Replay independently derived all 495 artifacts and their provenance. Both runs produced a byte-identical immutable inventory.
- WSL2 SquashFS integration kept ordinary `dev/` files, recorded the fixed exclusion for block and character devices there, and refused a device outside `dev/` and a forged listing. Synthetic timeout, forced interruption and retry, process-tree cleanup and delegated cgroup memory tests passed.
- The real WRX36 extraction published 944 regular files totaling 24,369,968 bytes, matching an independent numeric SquashFS listing. It stored 238 symlink targets as metadata and recorded the `dev/` exclusion. Source replay and the archive report comparison passed. A DrvFs destination failed with the no-replace diagnostic and left no stage.
- Both RustSec lockfile audits passed. All nine AddressSanitizer fuzz targets completed 1,844,254 executions in total without a reported crash or timeout. ZIP and candidate discovery ran for approximately one minute each.

The native Windows comparison alternated 0.9.0 and 0.10.0 on NTFS, with eight workers, one warmup per binary and three timed fresh workspaces per workload. Artifact paths, digests and source ranges matched across releases. Peak RSS was unavailable in the Windows harness.

| Workload | 0.9.0 median | 0.10.0 median | 0.10.0 input throughput |
| --- | ---: | ---: | ---: |
| 512 small ZIP members | 2.581 s | 1.301 s | 0.05 MiB/s |
| 128 MiB sparse input | 0.688 s | 0.612 s | 209.1 MiB/s |
| Overlapping invalid uImage CRC claims | 0.367 s | 0.354 s | 90.4 MiB/s |
| SSC338Q | 2.419 s | 1.993 s | 10.9 MiB/s |

WRX36 recovery and SquashFS extraction on native WSL2 storage took a median of 2.52 s with two workers, approximately 5.0 MiB/s of input. Maximum observed peak RSS was 33.5 MiB. One warmup preceded three fresh workspace runs.

**NOT VERIFIED:** hosted CI execution, live Ghidra decompilation for 0.10.0, hardware flashing and general support beyond the format subset. No trusted Ghidra installation was present on the validation host.

## 0.9.0 archive compatibility

- Windows passed formatting, locked all-target check, Clippy with warnings denied, 98 tests, release build and rustdoc with warnings denied. Independent Python fixtures exercised four classic ZIP variants, including streamed stored and DEFLATE members, plus USTAR, replay and agent export. Malformed descriptor and TAR checksum cases left no published workspace.
- WSL2 passed formatting, locked all-target check, Clippy with warnings denied, all 98 tests and the locked release build after the SquashFS retry change.
- The real OpenWrt DL-WRX36 sysupgrade image matched the publisher digest. GNU tar and Python `tarfile` independently established three regular member ranges. The Windows release published byte-identical copies, replayed all three and verified a detached export. TAR members kept the unverified payload grade and the CRC-verified member count stayed zero.
- DTC, Python `zlib` and `unsquashfs` independently checked the two FDT ranges, one gzip member and one SquashFS range in the same input. All four pinned ranges matched the release scanner without budget exhaustion. [Reference manifest](tests/fixtures/reference/openwrt-wrx36-25.12.6.json)
- The prior OpenWrt EC330 G5U v1 and UniFi AC Lite inputs also passed scan and source replay on 0.9.0. All five annotated ranges matched.
- On WSL2 the WRX36 rootfs exposed an unprivileged device-node creation failure. The final strict retry succeeded with the root `dev/` subtree explicitly excluded. The workspace replayed and recorded 24,369,968 regular bytes, 1,310 admitted nodes and 238 symlinks as metadata.
- The Windows SSC338Q runs matched all 493 golden filenames and digests and replayed 495 artifacts. One and eight workers produced byte-identical workspaces. Bounded five-second TAR and ZIP fuzz runs passed with copied corpora, including the streamed ZIP seed.

Hosted CI, device flashing and recovery of arbitrary formats are outside this validation. Ghidra was not rerun for 0.9.0.

## 0.8.0 corpus, source mapping and agent export

- The release binary passed all six synthetic corpus cases. Seven independently expected findings matched, with no missing or extra validated findings in those cases.
- Windows release smoke verified a detached export, refused modified evidence, refused a changed byte map during replay after its hashes were rebuilt, and accepted replay and export of a workspace generated by the prior 0.7.1 binary.
- OpenWrt 25.12.6 sysupgrade images for the EC330 G5U v1 (ramips) and UniFi AC Lite (ath79) matched their official SHA-256 lists. Both SquashFS ranges were independently confirmed by `unsquashfs`. Python independently confirmed three uImage extents and both CRCs for each. The final corpus check matched all five ranges and reported no additional validated candidates or budget exhaustion. The reference labels are non-exhaustive. [Pinned OpenWrt references](tests/fixtures/reference/openwrt-25.12.6.json)
- Final Windows `analyze`, source replay and detached export passed for both real OpenWrt inputs. All five independently established ranges appear in their byte maps, including the SquashFS that follows a leading, valid uImage.
- The provisioned Linux gate passed with Ghidra 12.2 and Temurin 25.0.5. Two real headless runs yielded byte-identical functions, call graph, pseudocode and provenance. Exports included functions and pseudocode and were bound to the independently hashed ELF. Timeout, forced interruption and retry, process-tree cleanup and cgroup memory exhaustion also passed. [Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build) · [Temurin release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8)
- Both lockfile audits passed. The structured candidate fuzz target ran 43,390 executions in 61 seconds without a crash or timeout. Peak RSS was 483 MiB.
- The leading-uImage OpenWrt image passed source replay on Linux with its trailing SquashFS represented in the map.
- Final SSC338Q recovery with one and eight workers matched all 493 golden filenames and SHA-256 values, and replay checked all 495 source-derived artifacts. Both workspaces contained 545 files and were byte-identical.

The same-host WSL2 A/B comparison used the preserved 0.7.1 executable, eight workers and three measured runs per release after warmup. All four workloads produced identical source artifact hashes and ranges. The measurements used the 0.8.0 build before adding recognized-container tail discovery. None of these workloads takes that path.

| Workload | 0.7.1 median | 0.8.0 median | 0.7.1 / 0.8.0 max peak RSS |
| --- | ---: | ---: | ---: |
| Many small ZIP files | 0.841 s | 0.824 s | 5.88 / 5.95 MiB |
| 128 MiB sparse image | 0.495 s | 0.522 s | 132.91 / 132.84 MiB |
| Overlapping invalid uImage CRC claims | 0.227 s | 0.244 s | 36.96 / 37.10 MiB |
| SSC338Q | 1.338 s | 1.407 s | 83.43 / 84.22 MiB |

With three samples the reported p95 is the observed maximum. [Benchmark procedure](docs/corpus.md#controlled-performance-comparison)

**NOT VERIFIED:** hosted workflow execution, full hardware flash dumps and physical device recovery. The public corpus contains sysupgrade images and the SSC338Q update reference. Findings for these cases establish only the annotated byte ranges and replayed artifacts.
