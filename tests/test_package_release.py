"""Independent archive-reader checks for release packaging and metadata."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location(
    "package_release", Path(__file__).resolve().parents[1] / "scripts/package-release.py")
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def test_determinism_contents_permissions_and_identity_on_both_formats(self):
        for target, (executable, kind) in package.TARGETS.items():
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / executable
                binary.write_bytes(b"synthetic packaging fixture")
                record = package.package(binary, root / "first", "1.2.3", target, "a" * 40, 1794528000)
                repeated = package.package(binary, root / "second", "1.2.3", target, "a" * 40, 1794528000)
                self.assertEqual(record, repeated)
                data = (root / "first" / record["archive"]).read_bytes()
                self.assertEqual(data, (root / "second" / record["archive"]).read_bytes())
                self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
                self.assertEqual(len(data), record["size"])
                if kind == "zip":
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        contents = {info.filename: archive.read(info) for info in archive.infolist()}
                else:
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                        self.assertTrue(all(item.uid == item.gid == 0 for item in archive))
                        contents = {item.name: archive.extractfile(item).read() for item in archive}
                        self.assertEqual(archive.getmember(next(n for n in contents if n.endswith('/nyra-fw'))).mode, 0o755)
                self.assertEqual(len(contents), 4)
                payload = next(value for name, value in contents.items() if name.endswith('/' + executable))
                self.assertEqual(hashlib.sha256(payload).hexdigest(), record["binary_sha256"])
                self.assertEqual(payload, binary.read_bytes())
                self.assertTrue(all(name.startswith("nyra-fwlab-1.2.3-") and ".." not in name for name in contents))
                metadata = json.loads(next((root / "first").glob("*.json")).read_text())
                self.assertEqual(metadata, record)

    def test_invalid_source_identity_cannot_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version, commit in [("../../escape", "a" * 40), ("1.2.3", "invalid")]:
                with self.assertRaises(ValueError):
                    package.package(root / "missing", root / "output", version,
                                    "x86_64-unknown-linux-gnu", commit, 1794528000)
            self.assertFalse((root / "output").exists())

    def test_index_refuses_missing_platforms_and_modified_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture"
            binary.write_bytes(b"synthetic packaging fixture")
            records = [package.package(binary, root, "1.2.3", target, "a" * 40, 1794528000)
                       for target in package.TARGETS]
            document = package.assemble(records, root, "1.2.3", "a" * 40)
            self.assertEqual(len(document["artifacts"]), 2)
            sums = (root / "SHA256SUMS").read_text().splitlines()
            self.assertEqual(len(sums), 3)
            for line in sums:
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
            with self.assertRaises(ValueError):
                package.assemble(records[:1], root, "1.2.3", "a" * 40)
            archive = root / records[0]["archive"]
            archive.write_bytes(archive.read_bytes() + b"corruption")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                package.assemble(records, root, "1.2.3", "a" * 40)


if __name__ == "__main__":
    unittest.main()
