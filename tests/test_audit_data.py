import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.audit_data import audit_csv_files, audit_registry, normalized_fingerprint


class AuditDataTests(unittest.TestCase):
    def test_fingerprint_normalizes_case_and_whitespace(self):
        self.assertEqual(normalized_fingerprint(" Hello   WORLD "), normalized_fingerprint("hello world"))

    def test_cross_split_duplicate_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in (("train.csv", "Same prompt"), ("test.csv", " same   PROMPT ")):
                with (root / name).open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=["text", "label"])
                    writer.writeheader()
                    writer.writerow({"text": text, "label": "0"})
            findings, summary = audit_csv_files(root)
        self.assertEqual(summary["cross_split_duplicate_groups"], 1)
        self.assertIn("cross_split_duplicates", {item.code for item in findings})

    def test_large_prompt_is_audited_without_parser_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (root / "train.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["text", "label"])
                writer.writeheader()
                writer.writerow({"text": "x" * (129 * 1024), "label": "0"})
            findings, summary = audit_csv_files(root)
        self.assertEqual(summary["files"]["train.csv"]["prompts_over_128kib"], 1)
        self.assertIn("oversized_prompt", {item.code for item in findings})

    def test_approved_registry_requires_revision_and_license(self):
        entry = {
            "id": "example", "uri": "local://example", "role": "train_candidate",
            "threat_coverage": ["benign"], "languages": ["en"], "revision": None,
            "license_spdx": None, "review_state": "approved", "holdout": False, "notes": "test"
        }
        registry = {
            "registry_version": "test",
            "policy": {"allowed_roles": ["train_candidate"]},
            "datasets": [entry]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            findings, _ = audit_registry(path)
        codes = {item.code for item in findings}
        self.assertIn("approved_without_revision", codes)
        self.assertIn("approved_without_license", codes)


if __name__ == "__main__":
    unittest.main()
