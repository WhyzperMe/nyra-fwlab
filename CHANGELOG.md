# Changelog

## Unreleased

- Fix the benchmark fail-fast regression test on Windows by identifying temporary executables with `samefile` after path resolution. Exercise a path alias on every platform so this failure is covered locally.

- Qualify live Ghidra 12.2 with Linux JDK 25.0.5 on a known reference ELF and the SSC338Q ARM target. Strengthen the integration gate with actual decompilation, static-call and cache miss/hit assertions; document the tested scope and reproduction commands.

- Split CLI syntax, dispatch, scanning, analysis and output handling into focused modules. Retain command aliases and report bytes; reject `--ghidra-target` without headless configuration during argument parsing.
- Handle closed stdout pipes without a panic or misleading diagnostics. Keep other processing I/O errors fatal and make diagnostic writes best effort, including Ghidra cache messages.
- Bound Ghidra export bytes and collection sizes before allocation grows past admission limits. Reject duplicate/empty function entries and pseudocode attributed to failed decompilation.
- Cross-check Ghidra export bundles during fresh admission and cache reuse. Preserve ambiguous names and treat an index at its 20,000-function cap as potentially incomplete.
- Fail release comparisons immediately on different source/artifact identities instead of merely printing a false comparison flag.

- Bind checked byte ranges to their borrowed source and original or decoded-gzip coordinate identity. Reject decoded offsets at original candidate-carve boundaries; reuse range validation in byte maps and component graphs.
- Use typed internal filesystem and recovery states while retaining the existing public manifest fields and JSON labels.
- Enumerate RootFS once per publication and share admitted paths and fingerprints across ELF, checksum and hardware indexing. Reject conflicting observations, retain independent final snapshot verification and skip unrelated Stage 04 file opens.
- Add commit-pinned official Raspberry Pi boot-file references, independent ELF/FDT annotations and scheduled corpus/replay checks. Restrict repository downloads to pinned boot paths and reject cross-publisher redirects.
- Extend the release comparison harness to measure opt-in sandboxed extraction of the reference firmware.

- Centralize RootFS traversal on directory handles with no-follow, entry, path and deadline checks. Reuse it in ELF, extraction and hardware indexing.
- Read extracted ELF candidates, module metadata and configuration through checked file handles with bounded reads. Apply the invocation's limits in Stage 04.
- Reject expired publication budgets and invalid destination names before creating staging output or new parents.
- Document P0 safety contracts and their responsible modules and regression checks.

- Reject SquashFS root-inode references into the middle of metadata blocks and offsets beyond an uncompressed root block.
- Preserve unrelated partial downloads and existing corpus manifests on failure. Publish verified downloads from unique temporary files and keep `--only` manifests consistent with the selected cases.
- Stream cached-image hashing, reject oversized cached inputs and apply a download wall-clock budget.
- Enforce LF checkout for source and scripts, preserve binary fuzz seeds, ignore local environment files and run downloader regression tests in both CI platforms.
- Add a native release build that remaps local source paths, checks the CLI artifact for user-directory references and runs smoke tests directly against the checked binary.
- Prepare the local Git repository on `main` with Whyzper.Me as the project author.

## 0.10.1

- Validate the metadata block chains of a SquashFS, not only its superblock: inode and directory blocks, and the fragment, export and id tables with their indexes, down to the last byte of `bytes_used`. A scanner that only read the superblock called an image carvable whose tail was damaged. A superblock copied out of a UBI image looked complete while its tables were interleaved with erase-block headers. Two real OpenWrt images carried such a false, carvable SquashFS. Reports stay byte-identical unless a classification or the named failed check changes. Workspaces that carved such a SquashFS no longer replay and need regeneration from the verified original.
- Judge ZIP structure without the extraction policy. A ZIP whose records agree is a structure-validated, carvable candidate even when a member uses bzip2 or LZMA, has a non-ASCII, unsafe or repeated name or is a link. ZIP64 fields fail the new, separate check `zip_classic_32bit_records`.
- Treat a ZIP stored inside a ZIP member as its own nested candidate. Only local headers that the central directory lists are explained.
- Classify a valid archive that recovery cannot extract as `unsupported` instead of `structure_check_failed`: repeated or aliasing TAR member names, ZIP members outside the subset and ZIP64.
- Preserve the source with `--allow-partial` when valid input exceeds a resource limit, matching the candidate scan. An expired run deadline is still refused.
- Add an independent unseen-family corpus: `scripts/generate-unseen-corpus.py`, `scripts/independent-oracle.py`, `scripts/fetch-reference-corpus.py`, a pinned manifest of eleven real images from six more SoC families and an optional evidence tier per expected range. The result schema of `check-corpus.py` is version 2.
- Add `scripts/oracle-fuzz.py`, a differential fuzzer that compares the scanner with the independent oracle on mutated images. Differences that follow from a documented rule are named classes that the script verifies. Only an unexplained difference fails a run. It runs in CI.
- Seed and extend the ZIP, SquashFS and candidate fuzz targets with the new fixtures and invariants.

## 0.10.0

- Share typed ZIP and TAR structure findings across scan, workspace publication, source replay and detached agent export. Classic ZIP cross-checks central metadata in one index.
- Add a replayable component graph with separate original and decoded gzip address spaces, artifact links and SquashFS observations.
- Determine the fixed SquashFS `dev/` exclusion from bounded preflight listings. Keep strict extraction and validate the sandbox handoff.
- Add opt-in JSON phase timings on standard error, with unchanged workspace bytes. Diagnose unsupported atomic publication on WSL Windows mounts.
- Batch archive writes and stage hashing on the bounded Rayon pool. Cross-check the staged manifests against the fresh inventory before publication. Published-workspace verification independently recomputes file hashes.

## 0.9.0

- Index classic ZIP local records from the central directory. Verify signed and unsigned 32-bit data descriptors before decoding streamed stored and DEFLATE members.
- Recognize bounded USTAR and GNU TAR firmware. Copy regular members as unverified raw bytes, retain exact source ranges and replay them. Scan for embedded structures and allow a unique SquashFS member to enter optional extraction.
- Exercise streamed ZIP and TAR with independent Python fixtures. Add a dedicated TAR fuzz target.
- Retry the known unprivileged SquashFS device-node failure under `dev/` with a literal subtree exclusion and report the omitted subtree.

## 0.8.0

- Map physical source regions, candidate ranges, recovered artifact ranges and observed fill. Source replay re-derives the map.
- Scan beyond validated uImage and SquashFS boundaries when the tail contains additional data, preserving the original recovery policy.
- Export a minimal Claude/Codex evidence bundle with `export-agent` and validate it with `verify-agent-export`. The export requires source replay and copies a fixed list of JSON reports.
- Compare candidate offsets and extents with independently annotated firmware and synthetic references. Distinguish missing findings, false positives and unclassified evidence.
- Add alternating release benchmarks, structured candidate mutations, scheduled longer fuzz runs and a manually triggered Ghidra runner gate.
- Consolidate current documentation and remove obsolete generated fixture copies and the historical benchmark driver.
- Rust consumers use `inspect_all_verified` in place of the individual `stage03/04/05::inspect_verified` wrappers and `selected_string_hits` in place of `selected_strings`.
