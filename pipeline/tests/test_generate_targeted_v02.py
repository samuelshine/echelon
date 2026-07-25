import unittest
from collections import Counter

from scripts.generate_targeted_v02 import generate


class GenerateTargetedV02Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = generate()

    def test_pilot_is_balanced_and_unique(self):
        self.assertEqual(len(self.rows), 1200)
        self.assertEqual(sum("benign" in row["proposed_labels"] for row in self.rows), 600)
        self.assertEqual(len({row["candidate_id"] for row in self.rows}), 1200)
        self.assertEqual(len({row["text"] for row in self.rows}), 1200)

    def test_template_lineage_cap(self):
        counts = Counter(row["template_lineage"] for row in self.rows)
        self.assertLessEqual(max(counts.values()), 10)

    def test_transformations_are_matched(self):
        malicious = Counter(row["transformation"] for row in self.rows if row["family"] == "obfuscated_attack_v02")
        benign = Counter(row["transformation"] for row in self.rows if row["family"] == "encoded_benign_control_v02")
        self.assertEqual(malicious, benign)

    def test_all_rows_remain_pending(self):
        self.assertTrue(all(row["review_status"] == "pending" and not row["operational_content"] for row in self.rows))


if __name__ == "__main__":
    unittest.main()
