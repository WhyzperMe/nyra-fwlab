# Ghidra headless adapter

Provide an explicit Linux `support/analyzeHeadless` path with `--ghidra-headless`. The adapter uses bubblewrap and imports one parsed ELF through the ELF loader with external library loading disabled. It creates an ephemeral project inside the sandbox. Select a recovered member with `--ghidra-target` or let the pipeline choose from the parsed ELF inventory.

Install a JDK compatible with the Ghidra release. Set `NYRA_JAVA_HOME` to use a trusted JDK outside the system paths. The [validation record](../../VALIDATION.md) identifies the versions and inputs exercised.

The Java scripts export function metadata, static call references and bounded lens-related inferred pseudocode. Analysis timeout or missing exports fail publication. Exports live under `analysis/ghidra/results/` and provenance under `analysis/ghidra/provenance.json`. Firmware code remains data throughout the run.
