# P0 safety contracts

These contracts define the acceptance criteria for recovery and workspace publication.
The five Cargo crates retain their existing responsibilities. Changes to a contract
require a regression test and an explicit compatibility decision.

| Contract | Owner | Verification |
| --- | --- | --- |
| Every source range has a checked end and fits its containing bytes. | Format readers, `source_map`, `byte_map` and replay | Parser prefix tests and replay tests for false source ranges and transformations. |
| Original and decoded gzip coordinates have explicit identities. | Candidate discovery and `component_graph` | `component_graph_keeps_decoded_gzip_coordinates_separate`. |
| Workspace reads open each relative component without following links, then check the opened handle. | Workspace `files` and `rootfs` | Replacement-root and retained-handle tests. Extracted binaries use the same handle for prefix admission and bounded reading. |
| Traversal enforces entry, path-depth and deadline limits before accumulating an unbounded directory listing. | `rootfs`, `RunBudget` and shared path rules | Missing/empty extraction, entry-limit and expired-budget tests. |
| Configuration and module observations, file size and SHA-256 derive from the admitted file handle. | Stage 04 and `files` | File-size-change tests, hardware tests and real SquashFS extraction checks. |
| Expired publication budgets and invalid output names cause no staging writes or parent-directory creation. | `publish_directory` | `expired_publication_budget_does_not_start_writing` and `invalid_publication_name_leaves_its_parent_absent`. |
| A completed workspace becomes visible through one no-replace rename after verification. | `publish` and `integrity` | Concurrent-publication, disk-full cleanup and pre-rename manifest tests. |
| Integrity hashes, source replay and golden references establish different checks. | `verify`, `replay` and `golden` | Rehashed tampering tests, source replay and the independent SSC338Q reference. |
| Firmware content is data throughout static analysis and agent handoff. | Analysis, sandbox and guidance generator | Canonical guidance checks, detached export checks and sandbox integration gates. |

## File and resource boundaries

The input and output parents are selected by the operator. Use a controlled output parent.
Relative workspace reads descend through directory handles. An open file remains the
source of its read even if its pathname is subsequently replaced. Reads reject a size
change relative to the admitted handle and stay within the configured byte limit.

The RootFS enumerator distinguishes an absent extraction from an empty extraction.
It rejects links and special nodes. ELF indexing, extraction indexing and Stage 04
share this enumerator. Stage 04 receives the invocation budget instead of constructing
default limits for its filesystem analysis.

The CLI watchdog supplies the invocation wall-clock limit. Library budgets provide
cooperative checkpoints, including before staging starts and before final publication.
External tools remain opt-in and run through the Linux sandbox. Recovered firmware
is never executed or flashed.

## P0 qualification

Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md), the relevant negative tests,
the synthetic archive smoke gates, source replay and real SquashFS extraction.
When private SSC338Q fixtures are available, compare all 493 golden members and
replay all 495 artifacts. Record unavailable external gates as **NOT VERIFIED**.

The executed evidence and platform scope belong in [VALIDATION.md](../VALIDATION.md).
