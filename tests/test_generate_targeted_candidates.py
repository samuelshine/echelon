import unittest

from scripts.generate_targeted_candidates import generate_batch, transform_text


class TargetedCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = generate_batch()

    def test_batch_is_balanced_and_unique(self):
        self.assertEqual(len(self.rows), 6000)
        self.assertEqual(sum("benign" in row["proposed_labels"] for row in self.rows), 3000)
        self.assertEqual(len({row["candidate_id"] for row in self.rows}), 6000)

    def test_all_candidates_are_pending_and_non_operational(self):
        self.assertTrue(all(row["review_status"] == "pending" for row in self.rows))
        self.assertTrue(all(row["operational_content"] is False for row in self.rows))

    def test_encoded_controls_match_attack_transformations(self):
        malicious = {row["transformation"] for row in self.rows if row["family"] == "obfuscated_attack"}
        benign = {row["transformation"] for row in self.rows if row["family"] == "encoded_benign_control"}
        self.assertEqual(malicious, benign)
        self.assertEqual(malicious, {"base64", "hex", "url", "unicode_escape", "reverse"})

    def test_base64_wrapper_is_explicit(self):
        self.assertIn("base64", transform_text("hello", "base64"))


if __name__ == "__main__":
    unittest.main()
