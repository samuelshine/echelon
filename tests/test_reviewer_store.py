import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

from reviewer.store import (
    decision_report, export_resolved, import_reviews, initialize_database, next_item, save_review,
)


class ReviewerStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.queue = root / "queue.jsonl"
        rows = [
            {"candidate_id": "a", "text": "alpha", "family": "benign", "transformation": None,
             "proposed_labels": ["benign"], "nearest_existing": {"text": "private"}, "review": {}},
            {"candidate_id": "b", "text": "beta", "family": "attack", "transformation": "hex",
             "proposed_labels": ["prompt_injection"]},
        ]
        self.queue.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        self.db = root / "review.sqlite3"
        initialize_database(self.db, self.queue)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def review(item="a", reviewer="r1", decision="benign", labels=None, expert=False, **quality):
        return {
            "item_id": item, "reviewer_id": reviewer, "decision": decision,
            "labels": labels if labels is not None else (["benign"] if decision == "benign" else []),
            "rationale_code": "label_confirmed", "notes": None, "naturalness": quality.get("naturalness", 5),
            "intent_correct": quality.get("intent_correct", True),
            "labels_correct": quality.get("labels_correct", True),
            "non_operational": quality.get("non_operational", True),
            "is_expert_adjudication": expert,
        }

    def test_primary_assignment_blinds_labels_neighbor_and_prior_reviews(self):
        item = next_item(self.db, "r1")
        self.assertEqual(item["item"]["candidate_id"], "a")
        self.assertNotIn("proposed_labels", item["item"])
        self.assertNotIn("nearest_existing", item["item"])
        self.assertNotIn("review", item["item"])
        save_review(self.db, self.review())
        second = next_item(self.db, "r2")
        self.assertNotIn("primary_reviews", second["item"])

    def test_matching_quality_reviews_admit_and_export(self):
        save_review(self.db, self.review())
        save_review(self.db, self.review(reviewer="r2"))
        report = decision_report(self.db)
        self.assertEqual(report["training_eligible_items"], 1)
        accepted = export_resolved(self.db)
        self.assertEqual([row["candidate_id"] for row in accepted], ["a"])
        self.assertNotIn("nearest_existing", accepted[0])
        self.assertNotIn("proposed_labels", accepted[0])
        self.assertEqual(accepted[0]["labels"], ["benign"])

    def test_matching_labels_do_not_bypass_quality_gate(self):
        save_review(self.db, self.review(naturalness=3))
        save_review(self.db, self.review(reviewer="r2"))
        self.assertEqual(decision_report(self.db)["training_eligible_items"], 0)

    def test_disagreement_requires_distinct_expert(self):
        save_review(self.db, self.review())
        save_review(self.db, self.review(reviewer="r2", decision="malicious", labels=["prompt_injection"]))
        self.assertEqual(next_item(self.db, "expert", expert=True)["item"]["candidate_id"], "a")
        with self.assertRaisesRegex(ValueError, "submit only once"):
            save_review(self.db, self.review(reviewer="r1", expert=True))
        save_review(self.db, self.review(reviewer="expert", expert=True))
        self.assertEqual(decision_report(self.db)["training_eligible_items"], 1)
        with self.assertRaisesRegex(ValueError, "already has an expert"):
            save_review(self.db, self.review(reviewer="expert2", expert=True))

    def test_offline_import_is_atomic(self):
        reviews = [self.review(), self.review(reviewer="r1")]
        with self.assertRaisesRegex(ValueError, "submit only once"):
            import_reviews(self.db, reviews)
        self.assertEqual(decision_report(self.db)["review_records"], 0)

    def test_expert_cannot_review_agreement(self):
        save_review(self.db, self.review())
        save_review(self.db, self.review(reviewer="r2"))
        with self.assertRaisesRegex(ValueError, "only after"):
            save_review(self.db, self.review(reviewer="expert", expert=True))

    def test_database_rejects_different_queue(self):
        self.queue.write_text(json.dumps({"candidate_id": "changed", "text": "x", "family": "x"}) + "\n")
        with self.assertRaisesRegex(ValueError, "different queue"):
            initialize_database(self.db, self.queue)

    @unittest.skipUnless(importlib.util.find_spec("flask"), "Flask is not installed in this test environment")
    def test_http_requires_token_and_binds_local_contract(self):
        from reviewer.app import create_app

        app = create_app(self.db, "r" * 16, "e" * 16)
        client = app.test_client()
        self.assertEqual(client.get("/api/next?reviewer_id=r1").status_code, 401)
        response = client.get("/api/next?reviewer_id=r1&role=primary", headers={"X-Review-Token": "r" * 16})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
