#!/usr/bin/env bash
# Run on a trusted, provisioned Linux runner. No tools are downloaded here.
set -euo pipefail
binary=$(realpath "${1:?usage: check-ghidra-gate.sh /path/to/nyra-fw}")
headless=$(realpath "${NYRA_GHIDRA_HEADLESS:?set NYRA_GHIDRA_HEADLESS}")
: "${NYRA_JAVA_HOME:?set NYRA_JAVA_HOME}"
: "${NYRA_EXPECT_GHIDRA_VERSION:?set NYRA_EXPECT_GHIDRA_VERSION}"
: "${NYRA_EXPECT_JAVA_VERSION:?set NYRA_EXPECT_JAVA_VERSION}"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cat > "$work/reference.c" <<'EOF'
static int lens_focus_transform(int value) { return value * 3 + 1; }
int main(int argc, char **argv) { return lens_focus_transform(argc) == 4 && argv ? 0 : 1; }
EOF
cc -g -O0 "$work/reference.c" -o "$work/reference.elf"
for run in first second; do
  "$binary" analyze "$work/reference.elf" --workspace "$work/$run" \
    --ghidra-headless "$headless" --timeout-seconds 300
  "$binary" verify "$work/$run" --replay --agent-ready
done
mkdir "$work/cache"
for run in cache-miss cache-hit; do
  "$binary" analyze "$work/reference.elf" --workspace "$work/$run" \
    --ghidra-headless "$headless" --ghidra-cache "$work/cache" \
    --timeout-seconds 300 2>"$work/$run.log"
  "$binary" verify "$work/$run" --replay --agent-ready
done
grep -q '^nyra-fw: Ghidra cache miss$' "$work/cache-miss.log"
grep -q '^nyra-fw: Ghidra cache hit$' "$work/cache-hit.log"
python3 - "$work" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
paths = [root / run / "analysis/ghidra" for run in ("first", "second")]
relative = ["provenance.json", "results/functions.json", "results/callgraph.json", "results/pseudocode.json"]
for path in relative:
    assert (paths[0] / path).read_bytes() == (paths[1] / path).read_bytes(), path
provenance = json.loads((paths[0] / relative[0]).read_bytes())
assert provenance["target_sha256"] == hashlib.sha256((root / "reference.elf").read_bytes()).hexdigest()
assert provenance["ghidra_version"] == os.environ["NYRA_EXPECT_GHIDRA_VERSION"]
assert provenance["java_version_from_jdk_release"] == os.environ["NYRA_EXPECT_JAVA_VERSION"]
functions = json.loads((paths[0] / relative[1]).read_bytes())["functions"]
assert any(f["name"] == "lens_focus_transform" for f in functions)
calls = json.loads((paths[0] / relative[2]).read_bytes())["edges"]
assert any(e["caller"] == "main" and e["callee"] == "lens_focus_transform" for e in calls)
code = json.loads((paths[0] / relative[3]).read_bytes())["functions"]
assert any(f["name"] == "lens_focus_transform" and f["decompiled"] and f["pseudocode"].strip() for f in code)
outcomes = json.loads((root / "first/analysis/workspace/outcomes.json").read_bytes())
assert outcomes["ghidra"]["state"] == "completed"
cached = [root / run / "analysis/ghidra" for run in ("cache-miss", "cache-hit")]
for path in relative:
    assert (cached[0] / path).read_bytes() == (cached[1] / path).read_bytes(), path
    if path != "provenance.json":
        assert (paths[0] / path).read_bytes() == (cached[0] / path).read_bytes(), path
cached_provenance = json.loads((cached[0] / relative[0]).read_bytes())
for field, value in provenance.items():
    assert cached_provenance[field] == value, field
for field in ("ghidra_installation_sha256", "jdk_runtime_sha256"):
    value = cached_provenance[field]
    assert len(value) == 64 and all(c in "0123456789abcdef" for c in value), field
print("Ghidra repeatability, pinned versions, ELF provenance, real decompilation and cache miss/hit passed.")
PY
bash "$(dirname "$0")/check-linux-failure-gates.sh" "$binary"
