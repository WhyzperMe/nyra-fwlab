## What and why

## Evidence

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] A regression test fails without this change
- [ ] Firmware, logs and decompiler output stay data. Nothing new is executed or flashed.
- [ ] No firmware, keys, credentials, personal paths or host names are added
- [ ] Schemas under `schemas/` and `docs/` updated if a report changed
