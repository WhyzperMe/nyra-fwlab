# Testing

- `fixtures/synthetic/pihc-phase01.pkg`: deterministic, non-proprietary PIHC fixture with one original CRC-valid and one AES-transformed member.
- `fixtures/synthetic/phase01_golden.json`: expected output produced by the owner's original Python recovery script.
- Rust unit tests in each crate validate offset bounds, CRC/size checks, AES phase/rotation, path sanitization, error cases and on-disk verification.
- The format, workspace and CLI suites exercise candidate discovery, resource limits, deterministic recovery, replay and agent export.
- `python -B -m unittest discover -s tests -p "test_*.py"` checks download cleanup, selected manifests, cache and timeout limits, and release binary path checks without external network access.
- CI generates stored ZIP, DEFLATE ZIP and gzip reference outputs in its scratch directory. The checked-in gzip seed is used directly by Rust tests and fuzzing.
- The OpenWrt reference manifests contain only pinned URLs, digests and annotated ranges. [Corpus workflow](../docs/corpus.md)
- `fixtures/reference/raspberrypi-boot-pinned.json` adds official boot files from commit `12eeaa12865869b07db760f4bbb7507ec6f1976c`. `readelf -W -h -l -S` independently establishes the 2,305,632-byte ELF extent (section table at 2,303,792, 46 entries of 40 bytes); `dtc` and `fdtget` validate the 56,407-byte FDT. The opaque bootcode has no expected validated structure. Digests pin retrieved bytes; they are not publisher signatures or authenticity proofs. Store downloads outside the repository. These cases establish format behavior, not board support or complete recovery.
- `scripts/generate-unseen-corpus.py` builds valid, truncated, damaged and ambiguous images outside the repository with `mksquashfs`, `mkimage`, `dtc`, `ubinize`, Info-ZIP and Python. `scripts/independent-oracle.py` cross-checks them, and `scripts/check-corpus.py` compares the scanner with the result.
- Golden test against 493 files requires the user's private `firmware.pkg` and Python `recovery_manifest.json`, and is invoked via `nyra-fw verify --golden`.

The synthetic fixture was validated using the supplied reference script. A Rust toolchain is required to execute the Rust test suite.
