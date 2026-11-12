# Generated workspace schema

The runtime generator writes every file from parsed records. Nothing in a workspace is a static template.

| Location | Purpose |
| --- | --- |
| `original/` | Bounded source copy committed by SHA-256. |
| `recovered/` | Carves, CRC-verified update members and optional extracted filesystem files. |
| `analysis/` | Immutable structure, ELF, hardware and optional tool output. |
| `analysis/workspace/agent-index.json` | Roles, trust classes, checksums, tasks and reading order. [Agent workflow](agent-workflow.md) |
| `analysis/workspace/outcomes.json` | Structure, verified members, ELF coverage and portable optional-tool outcomes. |
| `analysis/archive/member-issues.json` | Absolute source offsets and reason codes for excluded archive records. |
| `analysis/archive/structure.json` | Structural finding shared with `scan --json` for standalone ZIP and TAR. Includes the archive extent and regular member header and payload offsets. |
| `analysis/workspace/components.json` | Structural observations for original bytes, carves and update members. |
| `analysis/workspace/component-graph.json` | Validated candidates, containment and overlap, original or decoded gzip coordinates, artifact provenance and SquashFS candidates. |
| `analysis/workspace/artifact-catalog.json` | File paths, hashes, evidence grades and source ranges where known. |
| `analysis/workspace/candidates.json` | Signature hits, checks, nesting, conflicts and next steps after validation failure, explicit selection or discovery beyond a recognized uImage or SquashFS. [Candidate discovery](candidates.md) |
| `analysis/workspace/byte-map.json` | Half-open ranges covering the source, with artifact and candidate claims and direct fill observations. Replay re-derives the map. |
| `analysis/workspace/candidate-selection.json` | Candidate ID and source SHA-256 for an explicit carve, used in source replay. |
| `recovered/images/candidates/` | Raw carves of validated, conflict-free candidates at exact source ranges. |
| `recovered/unverified/tar/` | Raw regular members of a structurally validated TAR with exact source ranges and no independent payload checksum. |
| `analysis/workspace/task-plan.json` | Evidence and prerequisites for follow-up analysis. |
| `manifests/firmware.json`, `manifests/analysis.json` | Versioned source, recovery and analysis contracts. |
| `manifests/stage03.json` through `manifests/stage06.json` | Stage summaries. Stage 06 adds run state, source identity and an offline reuse key. |
| `analysis/binaries/elf-index.json` and `analysis/stage03/` | Static ELF metadata, dependency resolution, addressed strings, security observations and boot candidates. |
| `analysis/hardware/` | Hardware observations, kernel module metadata and a lens evidence worklist. Configuration keys are reported without values. |
| `analysis/ghidra/` | Opt-in function, call graph and pseudocode exports with provenance bound to the analyzed ELF hash. |
| `analysis/filesystems/extraction.json` | Extracted byte and node counts, symlink count and explicit excluded subtrees. |
| `manifests/workspace-integrity.json` | Bounded SHA-256 inventory of the immutable file tree. |
| `reconstruction/` | Editable area excluded from the integrity inventory. |
| `AGENTS.md`, `CLAUDE.md` | Identical authored guidance populated by typed summary data, for Codex and Claude Code. |

Versioned JSON Schemas cover the agent index, export manifest, candidates, explicit selection, byte map, archive structure, component graph, tool outcomes and CLI timing records. [Schemas](../schemas/)

The byte map covers every original byte in ordered, disjoint regions. Claims retain their verification grade. Multiple claims can reflect a candidate and its own carve, containment or an actual conflict. Consult the candidate report for conflict decisions. Fill labels record uniform 4 KiB blocks of zero or `0xff` in unclaimed gaps. They establish byte values. Padding intent, partition boundaries and flash geometry require independent evidence.

The component graph includes the validated subset of the candidate report when discovery ran. Candidate IDs refer to that report. An offset in `decoded_gzip` is relative to the verified decoded payload identified by `container_candidate`. A candidate and its materialized carve may both appear as SquashFS references. Each reference records a structural observation. Identifying a booted root filesystem requires separate evidence. Source replay re-derives the graph, byte map and applicable archive structure.

The standalone archive finding reports header and payload locations in original bytes. A ZIP payload CRC in that report is the declared value cross-checked between ZIP records. Consult the recovery manifest for the actual verification outcome. The TAR field is null because the TAR header checksum covers metadata.

The run state is `recognized_members_verified`, `preserved_and_inspected` or `partial`. Extracted rootfs files and update ZIP members occupy separate directories. The verifier checks source ranges, hashes and cross-manifest consistency. Device-node references, sensor profile names and module ABI strings are static observations. Physical identity, compatibility and flash coverage require independent evidence. [Format support](formats.md)
