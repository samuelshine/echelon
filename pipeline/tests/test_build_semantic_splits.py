import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_semantic_splits import UnionFind, assign_splits, calibration_band, components, embedding_view, group_profile, is_mixed_safety, load_jsonl, pair_kind, split_label_balance


def sparse_category_records(sparse_rows: int = 40, bulk_rows: int = 960):
    """A corpus shaped like v0.3: one bulk category plus one very sparse one."""
    records = [
        {"record_id": f"bulk-{index}", "split": "train",
         "labels": ["benign"] if index % 2 else ["toxicity_harm"]}
        for index in range(bulk_rows)
    ]
    records += [
        {"record_id": f"sparse-{index}", "split": "train", "labels": ["malicious_code"]}
        for index in range(sparse_rows)
    ]
    return records


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

    def test_group_profile_counts_rows_benign_and_categories(self):
        records = [
            {"labels": ["benign"]},
            {"labels": ["prompt_injection", "system_prompt_leakage"]},
        ]
        profile = group_profile(records, [0, 1])
        self.assertEqual(profile["rows"], 2)
        self.assertEqual(profile["benign"], 1)
        self.assertEqual(profile["prompt_injection"], 1)
        self.assertEqual(profile["system_prompt_leakage"], 1)

    def test_sparse_category_reaches_every_split(self):
        records = sparse_category_records()
        assigned = assign_splits(records, [[index] for index in range(len(records))])
        balance = split_label_balance(records, assigned)
        for split in ("train", "validation", "test"):
            self.assertGreater(
                balance["label_occurrences"][split].get("malicious_code", 0), 0,
                f"{split} has no malicious_code positives",
            )
        self.assertEqual(balance["categories_absent_from_split"], {})

    def test_every_category_lands_near_the_requested_ratio(self):
        # The guarantee the stratified default buys: no category drifts far from
        # 80/10/10. On the real v0.3 corpus the unstratified allocation put
        # malicious_code at 77.6/3.6/18.8 and adversarial_obfuscation at
        # 85.9/9.5/4.6; that skew is what starved validation of a whole head.
        records = sparse_category_records()
        assigned = assign_splits(records, [[index] for index in range(len(records))])
        balance = split_label_balance(records, assigned)
        for category in ("benign", "toxicity_harm", "malicious_code"):
            per_split = {
                split: balance["label_occurrences"][split].get(category, 0)
                for split in ("train", "validation", "test")
            }
            total = sum(per_split.values())
            for split, expected in (("train", 0.8), ("validation", 0.1), ("test", 0.1)):
                self.assertAlmostEqual(
                    per_split[split] / total, expected, delta=0.03,
                    msg=f"{category} in {split} drifted from the requested ratio",
                )

    def test_unstratified_allocation_remains_available_for_reproduction(self):
        records = sparse_category_records()
        assigned = assign_splits(
            records, [[index] for index in range(len(records))], stratify_labels=False,
        )
        rows = {split: sum(len(group) for group in groups) for split, groups in assigned.items()}
        self.assertEqual(sum(rows.values()), len(records))
        self.assertAlmostEqual(rows["train"] / len(records), 0.8, delta=0.02)

    def test_stratification_preserves_overall_ratios(self):
        records = sparse_category_records()
        assigned = assign_splits(records, [[index] for index in range(len(records))])
        rows = {split: sum(len(group) for group in groups) for split, groups in assigned.items()}
        self.assertAlmostEqual(rows["train"] / len(records), 0.8, delta=0.02)
        self.assertAlmostEqual(rows["validation"] / len(records), 0.1, delta=0.02)
        self.assertAlmostEqual(rows["test"] / len(records), 0.1, delta=0.02)

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
