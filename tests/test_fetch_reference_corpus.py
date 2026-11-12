"""Regression checks for the downloader, using in-memory publisher responses."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "fetch_reference", Path(__file__).resolve().parents[1] / "scripts/fetch-reference-corpus.py",
)
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)
DATA = b"synthetic reference bytes"
DIGEST = hashlib.sha256(DATA).hexdigest()
URL = "https://downloads.openwrt.org/reference.bin"


class MemoryPublisher:
    def open(self, url, timeout):
        return io.BytesIO(DATA)


class FetchTests(unittest.TestCase):
    def test_cleanup_never_removes_an_existing_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "image.bin"
            other_partial = root / "image.bin.part"
            other_partial.write_bytes(b"another process owns this")
            fetch.download(MemoryPublisher(), URL, destination, DIGEST)
            self.assertEqual(destination.read_bytes(), DATA)
            self.assertEqual(other_partial.read_bytes(), b"another process owns this")

    def test_failed_digest_keeps_the_previous_destination_and_removes_own_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "image.bin"
            destination.write_bytes(b"previous verified image")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                fetch.download(MemoryPublisher(), URL, destination, "0" * 64)
            self.assertEqual(destination.read_bytes(), b"previous verified image")
            self.assertEqual(list(root.iterdir()), [destination])

    def test_download_limit_leaves_no_destination_or_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(fetch, "MAX_IMAGE_BYTES", 2), self.assertRaisesRegex(ValueError, "size bound"):
                fetch.download(MemoryPublisher(), URL, root / "image.bin", DIGEST)
            self.assertEqual(list(root.iterdir()), [])

    def test_wall_clock_budget_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(fetch.time, "monotonic", side_effect=[0, fetch.DOWNLOAD_SECONDS]):
                with self.assertRaises(TimeoutError):
                    fetch.download(MemoryPublisher(), URL, root / "image.bin", DIGEST)
            self.assertEqual(list(root.iterdir()), [])

    def test_cache_rejects_an_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.bin"
            image.write_bytes(DATA)
            self.assertTrue(fetch.cached_image_matches(image, DIGEST))
            with patch.object(fetch, "MAX_IMAGE_BYTES", 2):
                self.assertFalse(fetch.cached_image_matches(image, DIGEST))

    def test_selected_manifest_is_self_consistent_and_can_be_reused_as_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, output = root / "reference.json", root / "output"
            manifest.write_text(json.dumps({"schema_version": 1, "cases": [
                {"id": name, "file": name + ".bin", "sha256": DIGEST, "source_url": URL}
                for name in ("first", "second")
            ]}))
            for source in (manifest, output / "corpus.json"):
                with patch.object(sys, "argv", ["fetch", str(source), str(output), "--only", "second"]):
                    with patch.object(fetch.urllib.request, "build_opener", return_value=MemoryPublisher()):
                        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
                            fetch.main()
                self.assertEqual(exit.exception.code, 0)
            selected = json.loads((output / "corpus.json").read_bytes())
            self.assertEqual([case["id"] for case in selected["cases"]], ["second"])
            self.assertFalse((output / "first.bin").exists())

    def test_publisher_commit_pins_and_cross_publisher_redirects(self):
        valid = "https://raw.githubusercontent.com/raspberrypi/firmware/" + "a" * 40 + "/boot/start4.elf"
        fetch.check_url(valid)
        for url in [valid.replace("a" * 40, "stable"), valid.replace("raspberrypi/firmware", "other/firmware"), valid + "?query", valid + "#fragment"]:
            with self.assertRaises(ValueError):
                fetch.check_url(url)
        request = fetch.urllib.request.Request(URL)
        with self.assertRaises(fetch.urllib.error.URLError):
            fetch.SameHostRedirect().redirect_request(request, None, 302, "", {}, valid)

    def test_redirect_urls_reject_credentials_and_nonstandard_ports(self):
        redirect = fetch.SameHostRedirect()
        for url in (
            "http://downloads.openwrt.org/image.bin",
            "https://other.invalid/image.bin",
            "https://user:secret@downloads.openwrt.org/image.bin",
            "https://downloads.openwrt.org:8443/image.bin",
        ):
            with self.assertRaises(fetch.urllib.error.URLError):
                redirect.redirect_request(None, None, 302, "", {}, url)

    def test_failed_download_does_not_replace_an_existing_corpus_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "reference.json", root / "output"
            output.mkdir()
            manifest = output / "corpus.json"
            manifest.write_bytes(b"previous manifest")
            source.write_text(json.dumps({"schema_version": 1, "cases": [{
                "id": "image", "file": "image.bin", "sha256": "0" * 64, "source_url": URL,
            }]}))
            with patch.object(sys, "argv", ["fetch", str(source), str(output)]):
                with patch.object(fetch.urllib.request, "build_opener", return_value=MemoryPublisher()):
                    with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
                        fetch.main()
            self.assertEqual(exit.exception.code, 1)
            self.assertEqual(manifest.read_bytes(), b"previous manifest")
            self.assertEqual(list(output.iterdir()), [manifest])


if __name__ == "__main__":
    unittest.main()
