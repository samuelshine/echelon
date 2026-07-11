import unittest

from scripts.validate_adjudications import summarize, validate_review


class ValidateAdjudicationsTests(unittest.TestCase):
    def test_benign_review_requires_only_benign_label(self):
        review = {"item_id": "x", "reviewer_id": "r1", "decision": "benign",
                  "labels": ["prompt_injection"], "rationale_code": "context", "is_expert_adjudication": False}
        self.assertTrue(validate_review(review, 1))

    def test_two_matching_reviewers_resolve_item(self):
        reviews = [
            {"item_id": "x", "reviewer_id": "r1", "decision": "benign", "labels": ["benign"]},
            {"item_id": "x", "reviewer_id": "r2", "decision": "benign", "labels": ["benign"]},
        ]
        self.assertEqual(summarize(reviews)["status"]["resolved_by_agreement"], 1)

    def test_disagreement_requires_expert(self):
        reviews = [
            {"item_id": "x", "reviewer_id": "r1", "decision": "benign", "labels": ["benign"]},
            {"item_id": "x", "reviewer_id": "r2", "decision": "malicious", "labels": ["prompt_injection"]},
        ]
        self.assertEqual(summarize(reviews)["status"]["needs_expert_adjudication"], 1)


if __name__ == "__main__":
    unittest.main()
