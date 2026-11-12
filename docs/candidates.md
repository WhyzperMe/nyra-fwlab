# Candidate discovery for unknown and damaged input

Unrecognized or damaged input goes through a bounded search for embedded structures. The search runs in `nyra-fw scan` and, when the input fails validation, in `analyze --allow-partial`. A recognized uImage or SquashFS with bytes beyond its validated end also gets a candidate report if the tail contains values other than `0x00` or `0xff`. Additional structures appear as evidence, with explicit selection available for separate carving. Use `scan --candidates` to request discovery for any outer format. Without `--allow-partial`, an unrecognized or damaged input publishes no workspace.

## Evidence tiers

| Status | Meaning |
| --- | --- |
| `signature_only` | Magic bytes matched. The reason records a missing parser or a validation, decompression, attempt or ZIP end-record budget. |
| `structure_validated` | Named checks on the candidate's own bytes passed. Extent is recorded only when those checks prove it. |
| `payload_verified` | A payload checksum of that candidate passed (gzip CRC32 and ISIZE, uImage header and payload CRC32). |
| `rejected` | A parser ran and a named check failed. The failed check is the last entry in `checks`. |

A hit inside another candidate needs its own check. Two exceptions are counted in `hits_explained_by_structure` and not listed: local headers that a validated ZIP's own central directory lists as member headers, and xz, bzip2 or zstd streams inside a validated SquashFS, where the filesystem itself accounts for them. An archive stored in a ZIP member starts at an offset the directory does not list. It is checked on its own and reported as a nested candidate.

## Selection and ambiguity

`nested_in` names the smallest validated candidate that contains another. `conflicts_with` lists validated candidates that overlap without containment, or that claim the same first byte as a different format. A candidate is `carvable` only when it is top-level, has a proven extent and has no conflict. Ambiguity is never resolved by order or size. `outcome` is one of `no_signatures`, `signatures_without_validation`, `single_structure`, `multiple_disjoint_structures` or `ambiguous`.

## Formats and what each check establishes

| Kind | Checks | Extent | Decoder in this build |
| --- | --- | --- | --- |
| ZIP | End, central and local records agree on names, flags, method, CRC32, sizes and exact tiling. This is judged without the extraction policy: a member with a method this build cannot decode, a name it refuses or a special node does not invalidate the structure. Member checksums are not decoded here. ZIP64 fields fail the separate check `zip_classic_32bit_records`. Each end record is matched to its inferred archive start before validation. | yes | stored and DEFLATE members |
| gzip | Header, DEFLATE, CRC32, ISIZE. The member may be followed by other bytes. | yes | yes |
| SquashFS 4.0 | Superblock fields, table offsets and the metadata block chains. Inode and directory blocks must end exactly where the next table begins. The fragment, export and id tables are each a run of blocks followed by an index: the runs must follow without gaps, every index entry must name the start of a real block and the last index must end the image. An image with an extended attribute table is checked up to its directory table. Metadata is not decompressed. | `bytes_used` | validation only; extraction is opt-in |
| uImage | Header and payload CRC32. | yes | yes |
| ELF | Class, encoding, header size, table bounds, segment and section ranges. | yes | static analysis |
| FDT | Header, aligned block bounds, reservation-map terminator, balanced node structure and bounded property names and values. | `totalsize` | no |
| PIHC | Header and archive offset. | no | recovery requires the input to start at offset 0 |
| UBI | Erase-counter header fields and CRC32. | no | no |
| xz | Stream header and CRC32. | no | no |
| bzip2, zstd, SquashFS big-endian | Signature only. | no | no |

Validated candidates without a decoder are findings, not support.

A SquashFS copied out of a container that interleaves its own headers, such as the erase blocks of a UBI image, fails the chain check even though its superblock is plausible, and `unsquashfs` cannot list it either. Its xz block streams are then no longer explained by a filesystem and appear as separate candidates.

## Bounds

| Bound | Value |
| --- | --- |
| Hits examined per signature | 4,096 (excess counted in `hits_not_examined`) |
| Validation attempts | 512 |
| Decoded bytes across all gzip attempts | 128 MiB, and the 32 MiB entry limit per member |
| Bytes charged to expensive validation | 512 MiB across ZIP spans, FDT extents, uImage CRC payloads and gzip input |
| Plausible ZIP end records per region | 4,096, with the excess recorded in `zip_ends_not_examined` |
| Nesting through verified gzip payloads | 2 levels below the source |
| Candidates in a report | 2,048 |
| Carves per workspace | 64, within the 256 MiB output limit |

`budget_exhausted` is true when a scan bound cuts the search short. Failed gzip and uImage attempts consume budget. Carve publication has its own bounds.

## Workspace output

With `--allow-partial` the workspace holds the source, `analysis/workspace/candidates.json` (schema 2) and raw carves up to the publication limits. Each carve records the exact source range and parent SHA-256. The verification grade is `original_crc32` for `payload_verified` candidates and `header_validated` for other published carves. A unique carved SquashFS becomes the image for opt-in extraction. The task plan includes `triage-candidates`.

```bash
nyra-fw scan flash.bin --candidates --json
nyra-fw analyze flash.bin --allow-partial --candidate 3 --workspace workspaces/selected
nyra-fw verify workspaces/selected --replay --agent-ready
```

Use the ID from the scan of the same source bytes and tool version. Explicit selection publishes only that carve and records the ID in `candidate-selection.json`. A selection requires a validated, top-level range with no observed conflict and a scan that finished within its bounds. A selected ELF enters static analysis. A selected SquashFS can enter opt-in extraction. A ZIP, gzip or uImage carve can be analyzed separately as a standalone input.

`next_steps` are selected by typed codes from the findings and contain fixed text. They never include strings taken from the firmware. A high-entropy or padding observation is a heuristic over 64 KiB blocks and does not distinguish compression, encryption and random data.

## Replay

`verify --replay` re-runs the scan on `original/`, compares the report, applies the recorded selection if present and compares the carves with the manifest. Older candidate workspaces can still pass snapshot verification. Regenerate them from the verified original for replay with the current scanner schema. A scanner correction can also change how a structure is classified, for example a SquashFS carve whose tables were never contiguous. Replay then reports that the candidate report differs from the report derived from the source, and the workspace has to be regenerated.
