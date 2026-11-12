# Security policy

NYRA FWLab parses untrusted firmware offline. It never executes extracted code, flashes a device or moves a motor.

## Reporting

Report a vulnerability privately through the repository's security advisory form. Do not open a public issue and do not attach proprietary firmware. Include the command, the version and a minimal input or its SHA-256. Examples of in-scope findings: a crash, a hang or unbounded memory on hostile input, a path that escapes the workspace, a published workspace that verifies but misstates provenance, and an external tool running outside its sandbox.

## What the tool does and does not defend

The threat model, limits and sandbox are in [docs/security.md](docs/security.md). Checksums and `verify --replay` detect corruption and inconsistent provenance. They do not authenticate the vendor, and anyone who can rewrite a whole workspace can rewrite its hashes.

## Constants in the source

`crates/nyra-fw-formats/src/pihc/crypto.rs` contains three 16-byte AES constants that restore the update-package obfuscation used by HiChip PIHC files. They are format constants recovered from a vendor update package, not credentials of this project or of any account, and they protect nothing in this repository. Review the licensing of those constants and of any firmware you analyze before redistributing them.

## Supply chain

Dependencies are pinned by `Cargo.lock` and `fuzz/Cargo.lock`. CI runs `cargo audit` on both. Workflow actions are pinned by commit.
