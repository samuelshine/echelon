import json
import tempfile
import unittest
from pathlib import Path

from echelon.training_gate import TrainingGateError, validate_training_manifest
from echelon.training_data import validate_split_rows


class TrainingGateTests(unittest.TestCase):
    def manifest(self):
        return {
            "eligible_for_training": True, "human_review_complete": True,
            "semantic_split_verified": True, "privacy_review_complete": True,
            "dataset_sha256": "a" * 64, "rows": 100,
            "splits": {"train": 80, "validation": 10, "test": 10},
        }

    def write(self, value):
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with handle:
            json.dump(value, handle)
        return Path(handle.name)

    def test_valid_manifest_passes(self):
        path = self.write(self.manifest())
        self.assertEqual(validate_training_manifest(path)["rows"], 100)
        path.unlink()

    def test_pending_manifest_is_blocked(self):
        value = self.manifest()
        value["eligible_for_training"] = False
        path = self.write(value)
        with self.assertRaisesRegex(TrainingGateError, "not marked eligible"):
            validate_training_manifest(path)
        path.unlink()

    def test_missing_approval_is_blocked(self):
        value = self.manifest()
        del value["human_review_complete"]
        path = self.write(value)
        with self.assertRaisesRegex(TrainingGateError, "human_review_complete"):
            validate_training_manifest(path)
        path.unlink()

    def test_split_validator_rejects_cluster_leakage(self):
        rows = [
            {"record_id": "a", "split": "train", "semantic_cluster_id": "g1", "training_eligible": True},
            {"record_id": "b", "split": "validation", "semantic_cluster_id": "g1", "training_eligible": True},
            {"record_id": "c", "split": "test", "semantic_cluster_id": "g2", "training_eligible": True},
        ]
        with self.assertRaisesRegex(ValueError, "cross split"):
            validate_split_rows(rows)

    def test_split_validator_accepts_disjoint_groups(self):
        rows = [
            {"record_id": "a", "split": "train", "semantic_cluster_id": "g1", "training_eligible": True},
            {"record_id": "b", "split": "validation", "semantic_cluster_id": "g2", "training_eligible": True},
            {"record_id": "c", "split": "test", "semantic_cluster_id": "g3", "training_eligible": True},
        ]
        self.assertEqual(validate_split_rows(rows), {"test": 1, "train": 1, "validation": 1})


if __name__ == "__main__":
    unittest.main()
