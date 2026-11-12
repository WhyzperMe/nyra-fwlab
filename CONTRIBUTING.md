# Contributing

Read [CLAUDE.md](CLAUDE.md) first. It states the architecture rules that every change must keep. [AGENTS.md](AGENTS.md) points coding agents to the same rules.

## License of contributions

Unless you state otherwise, a contribution you submit is licensed under the MIT License in `LICENSE`, without further terms.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python -B -m unittest discover -s tests -p "test_*.py"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --workspace --all-targets --release --locked
python -B scripts/build-release.py
```

For a parser change also run the matching fuzz target for a minute (`fuzz/README.md`). For a report change update the JSON Schema in `schemas/`. The schema test fails when a generated report and its schema disagree.

## Rules in short

- Organize code by responsibility. A module that grows past a few hundred lines or mixes concerns gets split. Reuse `magic`, `bytes` and `nyra_fw_core::path` instead of redefining signatures, readers or path rules.
- Non-test code must not panic on input: `unwrap`, `expect` and `panic!` are denied by workspace lints. Return an error.
- Add a failing regression test first. Negative tests for hostile input matter more than happy paths.
- Treat every input byte, name and string as data. Bound memory, time, depth and counts.
- Report only what a check established. Keep signature, structure-validated and payload-verified evidence apart.
- Keep output deterministic. Results must be byte-identical for any worker count.
- Do not commit firmware, extracted files, keys, workspaces, host names or personal paths. `workspaces/` and `target/` are ignored.
- Describe validation precisely, including what was not run.
- Use Whyzper.Me as the project author and maintainer. Preserve upstream attribution where required.
