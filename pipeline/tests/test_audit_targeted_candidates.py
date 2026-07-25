import unittest
from collections import Counter

from scripts.audit_targeted_candidates import lexical_metrics, overlap_bucket, stratified_review_sample


class AuditTargetedCandidatesTests(unittest.TestCase):
    def test_overlap_bucket_boundaries(self):
        self.assertEqual(overlap_bucket(0.97), "very_high_0.97_plus")
        self.assertEqual(overlap_bucket(0.94), "high_0.94_0.97")
        self.assertEqual(overlap_bucket(0.90), "boundary_0.90_0.94")
        self.assertEqual(overlap_bucket(0.89), "novel_below_0.90")

    def test_lexical_metrics_are_content_free_counts(self):
        metrics = lexical_metrics([{"text": "alpha beta"}, {"text": "alpha gamma"}])
        self.assertEqual(metrics["unique_tokens"], 3)
        self.assertEqual(metrics["unique_bigrams"], 2)

    def test_review_sample_balances_families(self):
        rows, neighbors = [], []
        for family in ("a", "b"):
            for index in range(10):
                rows.append({"candidate_id": f"{family}-{index}", "family": family,
                             "text": "x" * (index + 1), "transformation": None})
                neighbors.append({"similarity": 0.89, "record_id": "r", "source_id": "s", "labels": ["benign"], "text": "n"})
        sample = stratified_review_sample(rows, neighbors, per_family=4)
        self.assertEqual({family: sum(row["family"] == family for row in sample) for family in ("a", "b")}, {"a": 4, "b": 4})

    def test_review_sample_balances_transformations(self):
        rows, neighbors = [], []
        for transformation in ("base64", "hex"):
            for index in range(10):
                rows.append({"candidate_id": f"{transformation}-{index}", "family": "encoded",
                             "text": "x", "transformation": transformation})
                neighbors.append({"similarity": 0.89, "record_id": "r", "source_id": "s", "labels": ["benign"], "text": "n"})
        sample = stratified_review_sample(rows, neighbors, per_family=10)
        self.assertEqual(Counter(row["transformation"] for row in sample), Counter({"base64": 5, "hex": 5}))


if __name__ == "__main__":
    unittest.main()
