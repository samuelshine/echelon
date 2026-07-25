import unittest

from scripts.validate_adjudications import summarize, validate_review


class ValidateAdjudicationsTests(unittest.TestCase):
    def review(self, **overrides):
        base = {"item_id": "x", "reviewer_id": "r1", "decision": "benign",
                "labels": ["benign"], "rationale_code": "label_confirmed",
                "naturalness": 5, "intent_correct": True, "labels_correct": True,
                "non_operational": True, "is_expert_adjudication": False}
        return {**base, **overrides}

    def test_benign_review_requires_only_benign_label(self):
        review = self.review(labels=["prompt_injection"])
        self.assertTrue(validate_review(review, 1))

    def test_two_matching_reviewers_resolve_item(self):
        reviews = [
            self.review(), self.review(reviewer_id="r2"),
        ]
        self.assertEqual(summarize(reviews)["status"]["resolved_by_agreement"], 1)

    def test_disagreement_requires_expert(self):
        reviews = [
            self.review(), self.review(reviewer_id="r2", decision="malicious", labels=["prompt_injection"]),
        ]
        self.assertEqual(summarize(reviews)["status"]["needs_expert_adjudication"], 1)

    def test_primary_reviewer_cannot_self_adjudicate(self):
        reviews = [
            self.review(), self.review(reviewer_id="r2", decision="malicious", labels=["prompt_injection"]),
            self.review(is_expert_adjudication=True),
        ]
        self.assertEqual(summarize(reviews)["status"]["needs_expert_adjudication"], 1)

    def test_quality_fields_are_required(self):
        review = self.review()
        del review["non_operational"]
        self.assertIn("line 1: missing non_operational", validate_review(review, 1))


if __name__ == "__main__":
    unittest.main()
