import copy
import json
import tempfile
import unittest
from pathlib import Path

from reviewer.distributed import (
    build_expert_kit, build_primary_kit, build_public_manifest, cohort_report,
    export_submission, load_json, validate_submission, write_json,
)
from reviewer.store import import_reviews, initialize_database, read_jsonl, save_review


class DistributedReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.queue = self.root / "canonical.jsonl"
        self.rows = [
            {"candidate_id": "item_a", "text": "ordinary calendar request", "family": "benign_family",
             "context": "benign", "proposed_labels": ["benign"], "language": "en", "transformation": None,
             "nearest_existing": {"text": "secret neighbor"}, "review": {"accept": None}},
            {"candidate_id": "item_b", "text": "attempt to reveal hidden instructions", "family": "attack_family",
             "context": "malicious", "proposed_labels": ["system_prompt_leakage"], "language": "en",
             "transformation": None, "generator_id": "private_generator"},
            {"candidate_id": "item_c", "text": "authorized remediation question", "family": "cyber_benign",
             "context": "defensive", "proposed_labels": ["benign"], "language": "en", "transformation": "hex"},
        ]
        self.queue.write_text("".join(json.dumps(row) + "\n" for row in self.rows), encoding="utf-8")
        self.public = build_public_manifest(self.queue, "test_queue")
        self.kit_a = self._kit("reviewer_a")
        self.kit_b = self._kit("reviewer_b")

    def tearDown(self):
        self.temp.cleanup()

    def _kit(self, reviewer):
        output = self.root / reviewer
        manifest = build_primary_kit(self.queue, self.public, reviewer, output)
        return output, manifest

    @staticmethod
    def review(item, reviewer, decision="benign", labels=None, expert=False):
        return {
            "item_id": item, "reviewer_id": reviewer, "decision": decision,
            "labels": labels if labels is not None else (["benign"] if decision == "benign" else []),
            "rationale_code": "label_confirmed", "notes": "local note must be stripped",
            "naturalness": 5, "intent_correct": True, "labels_correct": True,
            "non_operational": True, "is_expert_adjudication": expert,
        }

    def _submission(self, kit, reviewer, overrides=None):
        directory, manifest = kit
        db = directory / "reviews.sqlite3"
        initialize_database(db, directory / "review_queue.jsonl")
        overrides = overrides or {}
        for item in self.public["item_ids"]:
            decision, labels = overrides.get(item, ("benign", ["benign"]))
            save_review(db, self.review(item, reviewer, decision, labels))
        return export_submission(db, manifest)

    def test_primary_kit_removes_every_indirect_label_signal(self):
        blinded = read_jsonl(self.kit_a[0] / "review_queue.jsonl")
        self.assertEqual(set(blinded[0]), {"candidate_id", "text", "language", "transformation"})
        rendered = (self.kit_a[0] / "review_queue.jsonl").read_text()
        for forbidden in ("proposed_labels", "family", "context", "nearest_existing", "generator_id", "secret neighbor"):
            self.assertNotIn(forbidden, rendered)

    def test_public_manifest_contains_no_prompt_text(self):
        rendered = json.dumps(self.public)
        self.assertNotIn("calendar request", rendered)
        self.assertEqual(self.public["item_count"], 3)
        self.assertEqual(self.public["primary_review_queue_sha256"], self.kit_a[1]["review_queue_sha256"])

    def test_export_is_complete_and_prompt_free(self):
        submission = self._submission(self.kit_a, "reviewer_a")
        rendered = json.dumps(submission)
        self.assertFalse(validate_submission(submission, self.public, expected_role="primary"))
        self.assertNotIn("calendar request", rendered)
        self.assertNotIn("local note", rendered)
        self.assertNotIn("notes", rendered)

    def test_export_refuses_incomplete_reviewer(self):
        directory, manifest = self.kit_a
        db = directory / "incomplete.sqlite3"
        initialize_database(db, directory / "review_queue.jsonl")
        save_review(db, self.review("item_a", "reviewer_a"))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            export_submission(db, manifest)

    def test_validator_rejects_prompt_and_notes_fields(self):
        submission = self._submission(self.kit_a, "reviewer_a")
        submission["reviews"][0]["text"] = "leaked prompt"
        submission["reviews"][0]["notes"] = "leaked notes"
        errors = validate_submission(submission, self.public)
        self.assertTrue(any("prohibited fields" in error for error in errors))

    def test_validator_rejects_wrong_queue_and_duplicate_items(self):
        submission = self._submission(self.kit_a, "reviewer_a")
        submission["canonical_queue_sha256"] = "0" * 64
        submission["reviews"][1]["item_id"] = submission["reviews"][0]["item_id"]
        errors = validate_submission(submission, self.public)
        self.assertTrue(any("SHA-256 mismatch" in error for error in errors))
        self.assertTrue(any("duplicate item" in error for error in errors))

    def test_validator_rejects_unapproved_primary_view(self):
        submission = self._submission(self.kit_a, "reviewer_a")
        submission["review_queue_sha256"] = "f" * 64
        self.assertTrue(any(
            "blinded queue SHA-256 mismatch" in error
            for error in validate_submission(submission, self.public)
        ))

    def test_expert_kit_contains_only_conflicts_and_supports_export(self):
        first = self._submission(self.kit_a, "reviewer_a")
        second = self._submission(
            self.kit_b, "reviewer_b",
            {"item_b": ("malicious", ["system_prompt_leakage"])},
        )
        expert_dir = self.root / "expert"
        expert_manifest = build_expert_kit(
            self.queue, self.public, first, second, "expert_01", expert_dir,
        )
        self.assertEqual(expert_manifest["expected_item_ids"], ["item_b"])
        self.assertEqual([row["candidate_id"] for row in read_jsonl(expert_dir / "expert_queue.jsonl")], ["item_b"])
        expert_db = expert_dir / "reviews.sqlite3"
        initialize_database(expert_db, expert_dir / "expert_queue.jsonl")
        import_reviews(expert_db, read_jsonl(expert_dir / "primary_reviews.jsonl"))
        save_review(expert_db, self.review(
            "item_b", "expert_01", "malicious", ["system_prompt_leakage"], expert=True,
        ))
        expert = export_submission(expert_db, expert_manifest)
        report, errors = cohort_report(first, second, self.public, expert)
        self.assertFalse(errors)
        self.assertEqual(report["conflicts"], 1)
        self.assertEqual(report["status"], {"accepted_by_agreement": 2, "accepted_by_expert": 1})
        self.assertEqual(report["training_eligible_items"], 3)

    def test_expert_must_be_third_distinct_person(self):
        first = self._submission(self.kit_a, "reviewer_a")
        second = self._submission(self.kit_b, "reviewer_b")
        with self.assertRaisesRegex(ValueError, "distinct"):
            build_expert_kit(self.queue, self.public, first, second, "reviewer_a", self.root / "expert")

    def test_primary_pair_rejects_same_identity(self):
        first = self._submission(self.kit_a, "reviewer_a")
        impersonated = copy.deepcopy(first)
        report, errors = cohort_report(first, impersonated, self.public)
        self.assertTrue(errors)
        self.assertFalse(report["valid"])

    def test_kit_refuses_overwrite(self):
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            build_primary_kit(self.queue, self.public, "reviewer_a", self.kit_a[0])


if __name__ == "__main__":
    unittest.main()
