import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from reviewer.distributed import build_primary_kit, build_public_manifest
from reviewer.sealed_kit import materialize_kit, seal_kit, unseal_kit


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography is not installed")
class SealedKitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.queue = self.root / "queue.jsonl"
        row = {
            "candidate_id": "candidate_1", "text": "private prompt text", "language": "en",
            "family": "malicious_family", "context": "malicious", "proposed_labels": ["prompt_injection"],
            "transformation": None,
        }
        self.queue.write_text(json.dumps(row) + "\n", encoding="utf-8")
        public = build_public_manifest(self.queue, "test")
        self.kit_dir = self.root / "kit"
        build_primary_kit(self.queue, public, "reviewer_a", self.kit_dir)
        self.sealed = self.root / "reviewer_a.echelonkit"
        self.passphrase = "correct horse battery staple 123"
        seal_kit(self.kit_dir, self.sealed, self.passphrase)

    def tearDown(self):
        self.temp.cleanup()

    def test_round_trip_materializes_hash_bound_kit(self):
        payload = unseal_kit(self.sealed, self.passphrase, "reviewer_a")
        queue_path, manifest_path = materialize_kit(payload, self.root / "runtime")
        self.assertIn("private prompt text", queue_path.read_text())
        self.assertEqual(json.loads(manifest_path.read_text())["assigned_reviewer_id"], "reviewer_a")

    def test_wrong_passphrase_fails_authentication(self):
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            unseal_kit(self.sealed, "incorrect passphrase value 123", "reviewer_a")

    def test_wrong_reviewer_cannot_open_kit(self):
        with self.assertRaisesRegex(ValueError, "different reviewer"):
            unseal_kit(self.sealed, self.passphrase, "reviewer_b")

    def test_ciphertext_tampering_fails_authentication(self):
        envelope = json.loads(self.sealed.read_text())
        envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
        self.sealed.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            unseal_kit(self.sealed, self.passphrase, "reviewer_a")


if __name__ == "__main__":
    unittest.main()
