# Parser fuzzing

The `cargo-fuzz` targets exercise the untrusted-input boundaries without writing
files or starting external tools. Every harness ignores inputs above 1 MiB and
uses reduced parser limits where the API supports them.

Targets cover PIHC header parsing, the PIHC AES transform and full recovery,
ZIP local and central directory scanning plus standalone archive recovery, bounded TAR indexing,
SquashFS and U-Boot image header inspection, ELF inspection, all three
Ghidra JSON exports (individual parsers and cross-export bundle consistency), and the candidate scanner (`fuzz_candidates`), which also
asserts report invariants such as extents inside the input and carvable-implies-no-conflict.

Install the nightly toolchain and `cargo-fuzz`, then run a target with:

```sh
cargo +nightly-2026-11-07 fuzz run --release fuzz_pihc_header -- -max_total_time=60 -max_len=1048576 -timeout=10 -rss_limit_mb=2048
```

The committed corpora contain the synthetic PIHC package, small ZIP archives
(including a nested, a bzip2 and a ZIP64 one), a real `mksquashfs` image,
synthetic SquashFS and U-Boot headers, a TAR with repeated member names,
truncated ELF magic, and minimal valid Ghidra exports. The ZIP target also
asserts that every archive recovery accepts passes the structure check, and the
candidate target asserts strict, validated containment. Keep generated crash artifacts and coverage reports out of source
control. CI runs every target for five seconds on changes and for 60 seconds in
scheduled or extended manual runs. Each input is capped at 1 MiB and ten
seconds, with a 2 GiB libFuzzer RSS limit.
