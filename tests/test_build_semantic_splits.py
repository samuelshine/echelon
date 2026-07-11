import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_semantic_splits import UnionFind, assign_splits, calibration_band, components, embedding_view, is_mixed_safety, load_jsonl, pair_kind


class SemanticSplitTests(unittest.TestCase):
    def test_union_find_components(self):
        union_find = UnionFind(4)
        union_find.union(0, 1)
        union_find.union(2, 3)
        self.assertEqual(sorted(map(len, components(union_find, 4))), [2, 2])

    def test_embedding_view_preserves_head_and_tail(self):
        view, truncated = embedding_view("a" * 3000 + "TAIL", max_chars=100)
        self.assertTrue(truncated)
        self.assertTrue(view.startswith("a" * 50))
        self.assertTrue(view.endswith("TAIL"))

    def test_mixed_safety_detection(self):
        records = [{"labels": ["benign"]}, {"labels": ["prompt_injection"]}]
        self.assertTrue(is_mixed_safety(records, [0, 1]))

    def test_publisher_test_group_never_moves_to_train(self):
        records = [
            {"record_id": "a", "split": "test", "labels": ["benign"]},
            {"record_id": "b", "split": "train", "labels": ["benign"]},
        ]
        assigned = assign_splits(records, [[0], [1]], preserve_publisher_holdouts=True)
        self.assertIn([0], assigned["test"])
        self.assertNotIn([0], assigned["train"])

    def test_fresh_partition_approximates_requested_ratios(self):
        records = [
            {"record_id": str(index), "split": "train", "labels": ["benign" if index % 2 else "toxicity_harm"]}
            for index in range(100)
        ]
        assigned = assign_splits(records, [[index] for index in range(100)])
        self.assertEqual({split: len(groups) for split, groups in assigned.items()},
                         {"train": 80, "validation": 10, "test": 10})

    def test_jsonl_loader_preserves_unicode_line_separator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            path.write_text(json.dumps({"text": "before\u2028after"}, ensure_ascii=False) + "\n", encoding="utf-8")
            self.assertEqual(load_jsonl(path)[0]["text"], "before\u2028after")

    def test_calibration_bands_have_explicit_boundaries(self):
        self.assertEqual(calibration_band(0.90), "0.90-0.92")
        self.assertEqual(calibration_band(0.94), "0.94-0.96")
        self.assertIsNone(calibration_band(0.8999))

    def test_pair_kind_marks_mixed_safety(self):
        self.assertEqual(pair_kind({"labels": ["benign"]}, {"labels": ["prompt_injection"]}), "mixed_safety")


if __name__ == "__main__":
    unittest.main()
