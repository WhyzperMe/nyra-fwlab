#!/usr/bin/env bash
# Independent SquashFS fixtures and checks for a provisioned Linux sandbox host.
set -euo pipefail

bin=$(realpath "${1:?usage: bash scripts/check-squashfs-gate.sh /path/to/nyra-fw}")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/source/dev" "$work/source/etc"
printf 'nyra rootfs fixture\n' > "$work/source/etc/data"
printf 'ordinary dev file\n' > "$work/source/dev/keep"
ln -s /etc/data "$work/source/link"

make_image() {
  local image=$1
  shift
  mksquashfs "$work/source" "$work/$image.squashfs" \
    -noappend -no-progress -processors 1 -all-root -no-xattrs "$@" >/dev/null
}

make_image ordinary
make_image dev-nodes -p 'dev/console c 600 0 0 5 1' -p 'dev/drive b 600 0 0 8 0'
make_image outside-dev -p 'etc/console c 600 0 0 5 1'
ln -s $'target\ncrw------- 0/0 5, 1 2000-01-01 00:00 /scratch/result/dev/fake' \
  "$work/source/dev/fake"
make_image forged-listing

for fixture in ordinary dev-nodes; do
  "$bin" analyze "$work/$fixture.squashfs" --extract-filesystems -o "$work/$fixture"
  "$bin" verify "$work/$fixture" --replay --agent-ready
done
for fixture in outside-dev forged-listing; do
  if "$bin" analyze "$work/$fixture.squashfs" --extract-filesystems -o "$work/$fixture"; then
    echo "unexpected success for $fixture" >&2
    exit 1
  fi
  test ! -e "$work/$fixture"
done

python3 - "$work" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for name, excluded in (("ordinary", []), ("dev-nodes", ["dev"])):
    workspace = root / name
    filesystem = workspace / "recovered/filesystems/rootfs"
    report = json.loads((workspace / "analysis/filesystems/extraction.json").read_bytes())
    links = json.loads((workspace / "analysis/filesystems/symlinks.json").read_bytes())
    assert report["excluded_subtrees"] == excluded, report
    assert links == [["link", "/etc/data"]], links
    assert not (filesystem / "link").is_symlink()
    assert (filesystem / "etc/data").read_bytes() == (root / "source/etc/data").read_bytes()
    assert not (filesystem / "dev/console").exists()
    assert not (filesystem / "dev/drive").exists()
    if excluded:
        assert not (filesystem / "dev").exists()
    else:
        assert (filesystem / "dev/keep").read_bytes() == (root / "source/dev/keep").read_bytes()
print("SquashFS sandbox gate passed")
PY
