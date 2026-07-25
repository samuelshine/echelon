import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.acquire_datasets import AcquisitionError, approved_sources, download_atomic, parse_hf_dataset_uri, resolve_url, verify_manifest


class AcquireDatasetsTests(unittest.TestCase):
    def test_parse_hf_uri(self):
        self.assertEqual(parse_hf_dataset_uri("hf://datasets/org/name"), "org/name")
        with self.assertRaises(AcquisitionError):
            parse_hf_dataset_uri("github://org/name")

    def test_resolve_url_pins_revision_and_quotes_path(self):
        revision = "a" * 40
        url = resolve_url("org/name", revision, "folder/a file.csv")
        self.assertIn(revision, url)
        self.assertIn("folder/a%20file.csv", url)

    def test_only_approved_sources_are_selected(self):
        base = {
            "uri": "hf://datasets/org/name", "revision": "a" * 40,
            "license_spdx": "Apache-2.0", "artifacts": ["README.md"]
        }
        registry = {"datasets": [
            {**base, "id": "yes", "review_state": "approved"},
            {**base, "id": "no", "review_state": "rejected"},
        ]}
        self.assertEqual([item["id"] for item in approved_sources(registry, None)], ["yes"])
        with self.assertRaises(AcquisitionError):
            approved_sources(registry, {"no"})

    def test_existing_artifact_is_hashed_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "artifact.bin"
            destination.write_bytes(b"already here")
            with patch("urllib.request.urlopen") as opener:
                digest, size = download_atomic("https://example.invalid/file", destination)
        opener.assert_not_called()
        self.assertEqual(size, 12)
        self.assertEqual(len(digest), 64)

    def test_manifest_verification_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "source" / ("a" * 40) / "file.bin"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"expected")
            manifest = root / "manifest.json"
            import hashlib, json
            manifest.write_text(json.dumps({"sources": [{
                "id": "source", "revision": "a" * 40,
                "artifacts": [{"path": "file.bin", "bytes": 8,
                               "sha256": hashlib.sha256(b"expected").hexdigest()}]
            }]}), encoding="utf-8")
            self.assertEqual(verify_manifest(manifest, root), [])
            artifact.write_bytes(b"tampered")
            self.assertTrue(verify_manifest(manifest, root))


if __name__ == "__main__":
    unittest.main()
