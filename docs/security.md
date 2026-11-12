# Security model

The input file, embedded paths, ZIP metadata, ELF tables, extracted files and all decompiler strings are untrusted. The configured workspace parent, operating-system packages, selected Ghidra installation, JDK and the account running the CLI are trusted. Share workspaces only with readers you trust to handle firmware contents. The snapshot detects corruption and cross-manifest inconsistencies. Anyone able to rewrite the entire workspace can also rewrite its hashes.

## Limits and publication

| Boundary | Default |
| --- | --- |
| Input | 512 MiB |
| Compressed or decoded member | 32 MiB |
| Declared decoded archive or extracted filesystem content | 256 MiB |
| Archive entries | 20,000 |
| ZIP member path | 512 bytes, at most 34 components |
| Workspace path | 1,024 bytes, at most 36 components |
| Immutable workspace verification | 2 GiB and 50,000 nodes |
| JSON manifests / individual analysis reports | 32 MiB / 64 MiB |
| Update ELF inspection | 512 candidates and 24 MiB aggregate ELF report |
| Ghidra export admission | 64 MiB per JSON, 128 MiB per bundle; 20,000 functions, 30,000 edges, 120 decompilation entries |
| Rayon CLI workers | Up to 8 automatically, 16 explicitly |
| CLI deadline / each external tool | 900 s / 300 s by default |
| Candidate scan | 4,096 hits per signature, 512 validation attempts, 512 MiB charged to expensive validation, 128 MiB decoded, 2 nesting levels, 2,048 candidates, 64 carves ([details](candidates.md)) |

The input uses a bounded read from a regular file handle. ZIP recovery enforces both compressed and declared uncompressed sizes before scheduling work. Exact DEFLATE stream end, byte counts and CRC precede publication. Traversal, Windows device names, case-folded aliases and conflicting file/directory prefixes are rejected. Standalone ZIP requires full agreement of local and central metadata. PIHC can recover verified local entries when directory metadata is damaged. Embedded containers in recognized input are identified at the first level and retained as bytes. Unrecognized or damaged input is searched for embedded structures under fixed bounds. Every candidate is validated on its own bytes, a gzip member is decoded only within the entry and aggregate limits, and overlapping validated candidates are never resolved automatically.

Publication uses a private, randomly named sibling stage, exclusive file creation and a verified directory rename that refuses an existing target on Linux and Windows. A forced process termination may leave a `.nyra-stage-*` sibling. Subsequent runs start in a fresh stage. Remove abandoned stages after confirming their writer has stopped. Atomic visibility is provided on supported filesystems. After power loss, re-run verification before using the workspace.

Use a native Linux workspace destination under WSL2. DrvFs can reject the no-replace rename required by publication. The staged output is discarded when that rename fails.

Verification opens workspace components using directory-relative handles without following links. It hashes immutable files with bounded buffers and checks the bytes of manifests it consumes against that inventory. Editable `reconstruction/` is excluded from hashing. Avoid editing the immutable workspace during a verification.

Run `verify --agent-ready` from a trusted directory before starting an agent in a generated workspace. It requires the current handoff, compares the instructions, index and task plan against the generator, and rejects unexpected root files and directories. Keep the verified directory under your control between verification and use. Treat editable reconstruction files and all evidence as untrusted inputs to the agent. [Agent workflow](agent-workflow.md)

## External tool boundary

External tools require explicit opt-in and Linux bubblewrap. A private user, PID and network namespace, cleared environment, read-only tool and input mounts, a 320 MiB scratch tmpfs and process resource limits bound the job. The sandbox has no writable host workspace mount. Its output is streamed into a bounded temporary file and admitted entry by entry. Special nodes and ambiguous paths are rejected. Symbolic links become metadata, and file permissions come from the host's file creation policy. A missing sandbox or rejected result fails the invocation by default. With `--allow-partial-tools`, completed steps contribute verified products and failed steps record fixed portable diagnostics in the workspace.

On Linux with an explicitly delegated cgroup v2 subtree, set `NYRA_CGROUP_PARENT` to apply a 2 GiB memory limit, zero swap and a 128-task limit across the external process tree. The parent must support memory and pids delegation. A requested group that cannot be configured fails that tool step. `--require-cgroup` also refuses external process launch without a delegated parent. A verified cache hit starts no external process. The optional controller is in addition to namespaces and per-process limits. [Linux cgroup v2 reference](https://docs.kernel.org/admin-guide/cgroup-v2.html)

SquashFS uses a bounded numeric inode listing of the literal root `dev/` subtree before extraction. If the listing shows a block or character device, the adapter cross-checks the record count and path form against a second path-only listing, then applies the fixed `dev` exclusion. This prevents a newline in a link target from adding a device record. The archive admission step verifies that the excluded subtree is absent and the extraction report records the omission. The listings and strict extraction share one sandbox deadline. Device nodes elsewhere fail the tool step. [Upstream listing format](https://github.com/plougher/squashfs-tools/blob/4.6.1/squashfs-tools/unsquashfs.c#L513)

The wrapper exposes the system runtime under `/usr` and selected system libraries and Java configuration read-only. Treat those paths and the explicitly mounted installation as trusted. Use a separate account or disposable VM when evaluating third-party tool builds or working with sensitive host data. A namespace sandbox shares the Linux kernel with the host.

Ghidra runs with the ELF loader on one validated input. Exports are bounded, checked and tied to a target SHA-256. A completed export can contain zero decompiled functions. Pseudocode is inferred and static references can miss indirect calls. Keep firmware strings, filenames, scripts and decompiler output in the evidence layer. Claude instructions come from authored templates and typed summaries.

Export counts are bounded while deserializing, before an excess entry is decoded.
Duplicate or empty function entries, contradictory decompilation status and
inconsistent export bundles are refused even if cache checksums agree. Duplicate
names remain ambiguous; an index capped at 20,000 entries cannot establish absence
of an unlisted function. Byte checksums alone do not prove semantic consistency.

No CRC or workspace hash authenticates the vendor. Physical hardware claims require independent evidence.

Use `verify --replay` to re-derive source artifacts and their provenance after the snapshot check. A workspace can be internally consistent even when a claimed transformation is wrong. The replay regression rehashes such a workspace and checks that the provenance verification rejects it.
