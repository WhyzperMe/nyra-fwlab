"""Regression checks for release comparison output identity."""
import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "compare_releases", Path(__file__).resolve().parents[1] / "scripts/compare-releases.py",
)
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


class CompareReleaseTests(unittest.TestCase):
    def setUp(self):
        self.identity = ("source-sha", (("recovered/file.bin", "artifact-sha", 10, 20),))

    def test_matching_source_and_artifact_identity_is_accepted(self):
        self.assertTrue(compare.require_matching_output_identities(self.identity, self.identity))

    def test_different_source_hash_fails(self):
        candidate = ("other-source-sha", self.identity[1])
        with self.assertRaisesRegex(RuntimeError, "source/artifact identities differ"):
            compare.require_matching_output_identities(self.identity, candidate)

    def test_different_artifact_hash_fails(self):
        candidate = (self.identity[0], (("recovered/file.bin", "other-artifact-sha", 10, 20),))
        with self.assertRaisesRegex(RuntimeError, "source/artifact identities differ"):
            compare.require_matching_output_identities(self.identity, candidate)

    def test_different_artifact_ranges_fail(self):
        for start, length in ((11, 20), (10, 21)):
            with self.subTest(start=start, length=length):
                candidate = (self.identity[0], (("recovered/file.bin", "artifact-sha", start, length),))
                with self.assertRaisesRegex(RuntimeError, "source/artifact identities differ"):
                    compare.require_matching_output_identities(self.identity, candidate)

    def test_main_fails_at_the_first_comparison_without_emitting_a_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            # Exercise a path alias on every host. Windows temp directories may
            # resolve through junctions; the stub must identify files, not paths.
            alias = Path(directory) / "alias"
            alias.mkdir()
            root = alias / ".."
            baseline, candidate, source = [root / name for name in ("baseline", "candidate", "input")]
            for file in (baseline, candidate, source):
                file.write_bytes(b"fixture")
            def measure(binary, *_):
                if binary.samefile(baseline):
                    identity = self.identity
                else:
                    self.assertTrue(binary.samefile(candidate))
                    identity = ("different-source", self.identity[1])
                return 0.1, 1.0, identity
            args = ["compare", "--baseline", str(baseline), "--candidate", str(candidate), "--iterations", "15"]
            output = io.StringIO()
            with patch.object(sys, "argv", args), patch.object(compare.subprocess, "check_output", return_value="fixture"):
                with patch.object(compare, "workloads", return_value={"fixture": source}):
                    with patch.object(compare, "measure", side_effect=measure) as measured:
                        with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "identities differ"):
                            compare.main()
            self.assertEqual(measured.call_count, 2)
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
