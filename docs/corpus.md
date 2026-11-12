# Firmware corpus and release comparisons

Keep licensed reference images in a private directory outside the checkout. The corpus checker reads a versioned manifest from that directory. Each case binds the input to its SHA-256 and records independently established structure locations. File names are relative to the manifest directory. The output includes case IDs and digests.

```bash
python3 scripts/generate-candidate-corpus.py /tmp/nyra-synthetic-corpus
python3 scripts/check-corpus.py --binary target/release/nyra-fw --manifest /tmp/nyra-synthetic-corpus/corpus.json
```

The generator builds six synthetic cases from Python ZIP, gzip and XZ readers and the independently generated DTC and UBI header fixtures. It includes invalid checksums, a truncated ZIP, padding and a damaged ELF prefix that precedes a valid ZIP. [Fixture recipes](../tests/fixtures/synthetic/README.md)

## Unseen-family corpus

A second corpus covers structures from families that the first one does not: all six SquashFS compressors, legacy uImage and FIT with embedded and external data, UBI and UBIFS, JFFS2, ZIP written by Info-ZIP and Python (data descriptors, extra fields, prefixed and adjusted offsets, bzip2, LZMA, ZIP64, unsafe, repeated and non-ASCII names, a ZIP inside a ZIP), gzip and xz variants, plus truncated, bit-flipped and overlapping variants of the valid parents. The pinned real images come from six more SoC families than the earlier references: Broadcom, Realtek, Marvell, Lantiq, MediaTek Filogic and Qualcomm IPQ40xx.

```bash
python3 scripts/generate-unseen-corpus.py ~/nyra-unseen/synthetic
python3 scripts/check-corpus.py --binary target/release/nyra-fw --manifest ~/nyra-unseen/synthetic/corpus.json
python3 scripts/fetch-reference-corpus.py tests/fixtures/reference/openwrt-unseen-25.12.6.json ~/nyra-unseen/real
python3 scripts/check-corpus.py --binary target/release/nyra-fw --manifest ~/nyra-unseen/real/corpus.json
```

Two independent paths decide the expectations. The generator states each expected structure by construction, and `scripts/independent-oracle.py` annotates the finished file without NYRA code: Python `zlib` and `zipfile`, `unsquashfs -ll` for SquashFS (the superblock alone is not enough), `mkimage` and `zlib.crc32` for uImage, `dtc` for FDT and the UBI and xz specifications for their headers. The generator refuses to write a corpus if the two disagree. The oracle does not annotate ELF, and it excludes ZIP64 archives and the xz, bzip2 and zstd streams that a validated SquashFS explains. Its scope is classic 32-bit ZIP records.

The real images are fetched from the publisher, never stored in the repository. `fetch-reference-corpus.py` accepts HTTPS on `downloads.openwrt.org` and commit-pinned `raspberrypi/firmware/<40-hex-commit>/boot/` files on `raw.githubusercontent.com`. Redirects stay on the initial publisher host, downloads are bounded and publication requires the pinned reference SHA-256. OpenWrt references use publisher digests; Raspberry Pi references pin the retrieved bytes without claiming publisher signatures. The manifest pins digests and independently annotated ranges. It is marked exhaustive because none of the images contains an ELF or PIHC signature. [Pinned manifest](../tests/fixtures/reference/openwrt-unseen-25.12.6.json)

The separate [Raspberry Pi boot reference](../tests/fixtures/reference/raspberrypi-boot-pinned.json) covers a VideoCore ELF, an FDT and opaque bootcode from an immutable upstream commit. ELF extents were annotated manually with `readelf`; the independent oracle validates FDT with `dtc`/`fdtget`. The opaque file has no validated candidate. This tests conservative behavior across a different ecosystem, not complete board recovery.

```bash
python3 scripts/fetch-reference-corpus.py tests/fixtures/reference/raspberrypi-boot-pinned.json ~/nyra-unseen/raspberrypi
python3 scripts/check-corpus.py --binary target/release/nyra-fw --manifest ~/nyra-unseen/raspberrypi/corpus.json
```

Pass `--only <case-id>` to fetch a subset. The output manifest lists the selected cases and can be reused as input. Downloads use unique temporary files. A failed download preserves the existing destination and corpus manifest. Cached images are hashed in chunks under the same size limit. A cooperative five-minute budget and 60-second socket timeouts bound download work.

## Differential fuzzing

`scripts/oracle-fuzz.py` mutates seed images deterministically (bit flips, truncation, insertion, deletion, zeroing, duplication, splicing). It scans each mutant with the release binary and annotates it with the independent oracle, then compares kind, offset, extent and evidence tier. The random seed reproduces the mutants.

```bash
python3 scripts/oracle-fuzz.py --binary target/release/nyra-fw --seeds ~/nyra-unseen/synthetic --output ~/nyra-unseen/fuzz --count 20000 --seed 1
```

Some differences are not defects, because the two sides apply different rules. Each is a named class that the script decides with its own check, not by assumption: DTB rules that `dtc` and libfdt skip (zero padding, an unnamed root node, `FDT_END` ending the structure block, a reservation terminator, versions 16 and 17), a SquashFS root inode reference whose upper bits the tools ignore, SquashFS metadata that the scanner does not decompress, tail tables that `unsquashfs` never reads, extra fields that the scanner does not parse and the ZIP `version needed` field that Python refuses. A mutant with an unexplained difference is kept in the output directory and fails the run. The report counts the explained differences per class.

Expected entries may carry `status` (`structure_validated` or `payload_verified`). The checker then compares the evidence tier as well as the range: only gzip and uImage have a payload checksum that the scanner verifies, and a ZIP whose member CRC is wrong is still a structure-validated candidate because recovery, not the scan, decodes members.

For a real input, record `id`, `file`, `sha256`, `exhaustive` and `expected` inside `cases`. Every expected entry has the scanner's `kind`, physical byte `offset` and either a byte `extent` and range `sha256`, or a null extent for a verified header with unknown length. Use an independent implementation for offsets and extents. For SquashFS, use `unsquashfs -offset <offset> -s <image>` and record the filesystem size it reports. Verify the publisher's image digest before recording the reference.

The manifest and comparison report have separate contracts. [Manifest schema](../schemas/candidate-corpus.schema.json) · [Result schema](../schemas/candidate-corpus-result.schema.json)

Use `exhaustive: true` only after annotating every supported structure. The checker reports unmatched findings as unclassified in partially annotated images. It fails on missing expected structures, wrong extents, extra validated findings in exhaustive cases or an exhausted scan budget. The measured scope is validated candidates in original input coordinates.

The public OpenWrt reference manifest pins the publisher's digests for two sysupgrade images. Copy the manifest into a private directory and place the files named in it alongside the manifest. Its `source_url` fields point to the publisher. SquashFS offsets and lengths were cross-checked with `unsquashfs`. uImage ranges were derived independently from header size, declared payload length and both CRCs using Python `zlib`. The two overlapping ranges in the EC330 image are distinct nested uImages. [Pinned OpenWrt references](../tests/fixtures/reference/openwrt-25.12.6.json)

The separate DL-WRX36 reference covers a real TAR sysupgrade with nested FIT/FDT, gzip and SquashFS. Python `tarfile` independently verified the raw member offsets and bytes. DTC, Python `zlib` and `unsquashfs` verified the annotated embedded structures. [Pinned DL-WRX36 reference](../tests/fixtures/reference/openwrt-wrx36-25.12.6.json)

Use `analyze --timings --json` to capture an additional versioned JSON record on standard error. It reports elapsed wall time, the outcome, worker count and measured phases. Analysis includes optional tool phases, so do not add phase durations to calculate elapsed time. For end-to-end comparisons, measure fresh workspaces on the same filesystem with the same worker count and capture peak resident memory separately. [Timing contract](../schemas/phase-timings.schema.json)

## Controlled performance comparison

```bash
python3 scripts/compare-releases.py --baseline /tmp/nyra-previous --candidate target/release/nyra-fw \
  --firmware /path/to/reference.pkg --threads 8 --iterations 5
```

Use `--extract-filesystems` with `--firmware` to include opt-in sandboxed extraction of the reference image on a provisioned Linux host. The generated workloads remain offline.

The script alternates launch order, discards one warmup per binary and uses fresh workspace destinations. A different source hash, artifact hash or source range aborts the comparison on the first pair, before a successful JSON report can be emitted. Workloads include many small files, a 128 MiB sparse image and overlapping invalid uImage CRC claims. It records median, nearest-rank p95, throughput, maximum observed peak RSS when GNU time is available, and whether artifact hashes and source ranges match. Pin the host, compiler, storage and input to interpret small differences. With five measurements, p95 is the maximum observed sample.

## Security gates

The CI fuzz job runs on changes and uses longer budgets on a weekly schedule or manual request. The candidate target mixes raw mutations with bounded edits to independently generated format fixtures.

Provision the separately labeled Linux runner with a trusted Ghidra installation, a compatible JDK, bubblewrap, util-linux, GNU tar, awk, squashfs-tools, Python 3, a C compiler and delegated cgroup v2 support. Set `NYRA_GHIDRA_HEADLESS` and `NYRA_JAVA_HOME` on the runner, and pin the expected release versions in the workflow variables `NYRA_GHIDRA_VERSION` and `NYRA_JAVA_VERSION`. The manually triggered workflow builds the locked release, checks SquashFS policy against independent images, checks fresh and cached Ghidra exports against one ELF hash, and runs process-tree and memory failure gates. Run the SquashFS checks alone with `bash scripts/check-squashfs-gate.sh target/release/nyra-fw`. [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)

Run the live Ghidra qualification locally in Linux or WSL with the same checked
release binary. The installation must include Linux support; a Windows Java
runtime cannot replace the Linux JDK inside the sandbox. The following example
uses the qualified version pair; substitute your trusted local installation paths:

```bash
export NYRA_GHIDRA_HEADLESS=/opt/ghidra_12.2_PUBLIC/support/analyzeHeadless
export NYRA_JAVA_HOME=/opt/jdk-25.0.5+8
export NYRA_EXPECT_GHIDRA_VERSION=12.2
export NYRA_EXPECT_JAVA_VERSION=25.0.5
bash scripts/check-ghidra-gate.sh target/release/nyra-fw
```

The gate compiles a known reference ELF without executing it, runs two fresh
headless analyses and checks identical exports and target SHA-256. It requires
the expected function, a static call from `main` and nonempty successful inferred
pseudocode. A separate cache miss/hit pair must be observed in the diagnostic
logs and produce identical results, with Ghidra/JDK fingerprints in provenance.
Every workspace passes replay and agent-ready verification. The final synthetic
failure gates check timeout, interruption, child cleanup and delegated-cgroup
memory pressure. Downloads and tool installation remain outside this script;
it never executes the imported ELF.
