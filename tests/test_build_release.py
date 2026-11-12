"""Privacy regression checks for the release artifact gate."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "build_release", Path(__file__).resolve().parents[1] / "scripts/build-release.py",
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_rejects_source_paths_in_both_binary_encodings(self):
        for encoding in ("utf-8", "utf-16le"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / "cli"
                source = str(Path(directory) / "private-source")
                binary.write_bytes(("prefix" + source + "/lib.rs").encode(encoding))
                with self.assertRaisesRegex(ValueError, "local build path"):
                    release.verify_binary(binary, [(source, "/nyra-fwlab")])

    def test_accepts_remapped_artifacts_and_rejects_other_user_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "cli"
            binary.write_bytes(b"/cargo-home/registry/src/dependency.rs")
            self.assertEqual(len(release.verify_binary(binary, [])), 64)
            self.assertEqual(len(release.verify_binary(binary, [("/cargo", "/other")])), 64)
            binary.write_bytes(b"/home/other-builder/project/source.rs")
            with self.assertRaisesRegex(ValueError, "user directory"):
                release.verify_binary(binary, [])


if __name__ == "__main__":
    unittest.main()
