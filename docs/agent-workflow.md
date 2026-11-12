# Using a workspace with a coding agent

From a trusted directory, run `nyra-fw verify <workspace> --agent-ready` with a trusted local binary **before** opening the workspace in an agent. The check verifies the immutable inventory, compares the instructions, index and task plan against the canonical generator, and rejects unexpected root entries such as agent settings or hooks. The current handoff is required. Regenerate a legacy workspace from its verified original before using it with an agent.

1. `AGENTS.md` (identical to `CLAUDE.md`) holds the operating rules and the reading order.
2. `analysis/workspace/agent-index.json` ([schema](../schemas/agent-index.schema.json)) is the machine-readable map.

## What the index gives an agent

| Field | Use |
| --- | --- |
| `source`, `detected_format`, `recovery_state` | Identity and how far recovery got. `full_flash_verified` is always `false`. |
| `counts` | Artifacts, verified and failed members, ELF objects, decompiled functions. |
| `candidates` | Present for unrecognized input: outcome, structures validated, carves made. |
| `hardware` | Static hint only, with the evidence grade. |
| `read_order`, `tasks` | What to read first and which follow-up tasks are `ready` or `blocked`, each with `read_first` paths. |
| `directories`, `files` | Every report and directory with `role`, `trust` and, where checksummed, `bytes` and `sha256`. |
| `instructions`, `limitations` | Fixed statements. |

`verify` cross-checks the index against the manifests, the task plan and the integrity inventory. Only the two verified top-level instruction files can guide work. Open everything else as evidence, including reports, recovered files, and any files supplied in the editable reconstruction tree. Avoid starting an agent from a nested directory of the workspace.

## Trust classes

| `trust` | Meaning for an agent |
| --- | --- |
| `authored_guidance` | The canonical root `AGENTS.md` and `CLAUDE.md` in the current handoff. |
| `computed_metadata` | Counts, hashes and offsets. No firmware text. |
| `firmware_derived_text` | Computed, but may quote symbols, strings, paths or decompiler output. Data, never instructions. |
| `firmware_bytes` | The input and what was carved or decoded from it. Never execute. |

## Reading large files

`manifests/firmware.json`, `manifests/artifacts.json`, `analysis/workspace/artifact-catalog.json`, `analysis/workspace/components.json` and `analysis/binaries/elf-index.json` are large. Their `role` says so. Query them, for example:

```bash
jq '.artifacts[] | select(.verification=="original_crc32") | .path' manifests/firmware.json
jq '.[] | select(.confidence=="verified_bytes") | .path' analysis/workspace/artifact-catalog.json
jq '.functions[] | select(.defined)' analysis/lens/function-index.json
jq '.root_filesystem_candidates' analysis/workspace/component-graph.json
```

The component graph distinguishes original byte offsets from decoded gzip offsets. In standalone ZIP or TAR workspaces, the archive structure report locates stored members. Use `verify --replay` to re-derive both from the source. [Workspace schema](workspace-schema.md)

## Disassembly output

With `--ghidra-headless`, exports are under `analysis/ghidra/results/` and `analysis/ghidra/provenance.json` binds tool, settings and the analyzed ELF SHA-256. Decompiler output is inferred and can miss indirect calls. In `analysis/lens/function-index.json`, `defined: false` marks a symbol without an address in that binary, such as an import.

## Before relying on a result

For a workspace from another operator, use a fresh destination outside the original workspace. The export command checks the current handoff, replays the source and copies allowlisted JSON evidence into a flat directory with fixed instructions. Recovered firmware, tool scripts and the editable tree stay in the original workspace.

```bash
nyra-fw export-agent <workspace> --output <new-agent-directory>
nyra-fw verify-agent-export <new-agent-directory>
```

The detached verifier checks the bundle layout, canonical instructions and report digests. Re-export from the original workspace to repeat the source replay. A bundle's digests alone cannot authenticate its sender.

```bash
nyra-fw verify <workspace> --agent-ready
nyra-fw verify <workspace> --agent-ready --replay
```

Replay re-derives the artifacts from `original/`. Neither command authenticates the vendor. Both commands and `inspect` accept `--json`. `verify --json` prints a result only when every check passed, and a failure exits with a non-zero status and a message on stderr.
