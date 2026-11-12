#!/usr/bin/env bash
# Synthetic sandbox fault tests. Requires Linux bubblewrap and a delegated systemd user session.
set -euo pipefail

bin=$(realpath "${1:?usage: bash scripts/check-linux-failure-gates.sh /path/to/nyra-fw}")
work=$(mktemp -d /tmp/nyra-failure-gates.XXXXXXXX)
tool="$work/ghidra"
marker="nyra-test-child-${work##*.}"
echo "Failure gate workspace $work"
mkdir -p "$tool/support" "$tool/Ghidra"
printf 'application.version=synthetic-test\n' > "$tool/Ghidra/application.properties"
touch "$tool/support/launch.sh" "$tool/support/launch.properties"
headless="$tool/support/analyzeHeadless"
unset NYRA_JAVA_HOME NYRA_CGROUP_PARENT

write_sleep_tool() {
  printf '#!/bin/bash\nbash -c '\''exec -a "%s" /usr/bin/sleep 90'\'' &\nwait\n' "$marker" > "$headless"
  chmod 700 "$headless"
}

wait_for_child() {
  for _ in $(seq 1 100); do
    if pgrep -f "^$marker 90$" >/dev/null; then return 0; fi
    sleep 0.05
  done
  return 1
}

assert_child_stopped() {
  for _ in $(seq 1 100); do
    if ! pgrep -f "^$marker 90$" >/dev/null; then return 0; fi
    sleep 0.05
  done
  return 1
}

write_sleep_tool
"$bin" analyze /usr/bin/true -o "$work/timeout" --ghidra-headless "$headless" \
  --timeout-seconds 10 --allow-partial-tools >"$work/timeout.log" 2>&1 &
pid=$!
wait_for_child
wait "$pid"
assert_child_stopped
grep -q 'wall-clock budget' "$work/timeout/analysis/workspace/outcomes.json"
"$bin" verify "$work/timeout"

"$bin" analyze /usr/bin/true -o "$work/retry" --ghidra-headless "$headless" >"$work/interrupted.log" 2>&1 &
pid=$!
wait_for_child
kill -KILL "$pid"
wait "$pid" && exit 1
assert_child_stopped
test ! -e "$work/retry"
"$bin" analyze /usr/bin/true -o "$work/retry"
"$bin" verify "$work/retry"

cat > "$headless" <<'PYTOOL'
#!/bin/sh
exec /usr/bin/python3 -c 'b = bytearray(192 * 1024 * 1024); b[::4096] = bytes(len(b) // 4096); print(len(b))'
PYTOOL
export NYRA_TEST_BIN="$bin" NYRA_TEST_WORK="$work" NYRA_TEST_HEADLESS="$headless"
# The delegated shell expands these variables after it enters the new scope.
# shellcheck disable=SC2016
systemd-run --user --scope --expand-environment=no -p Delegate=yes -p MemoryMax=128M bash -c '
  set -euo pipefail
  path=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
  mkdir "$path/control"
  printf "%s\n" "$$" > "$path/control/cgroup.procs"
  printf "+memory +pids\n" > "$path/cgroup.subtree_control"
  export NYRA_CGROUP_PARENT="$path"
  "$NYRA_TEST_BIN" analyze /usr/bin/true -o "$NYRA_TEST_WORK/memory" \
    --ghidra-headless "$NYRA_TEST_HEADLESS" --require-cgroup --allow-partial-tools
  grep -q '\''"state": "failed"'\'' "$NYRA_TEST_WORK/memory/analysis/workspace/outcomes.json"
  awk '\''$1 == "oom_kill" { found = $2 > 0 } END { exit !found }'\'' "$path/memory.events"
  "$NYRA_TEST_BIN" verify "$NYRA_TEST_WORK/memory"
'
