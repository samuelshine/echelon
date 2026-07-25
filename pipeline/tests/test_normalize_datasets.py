import unittest

from scripts.normalize_datasets import base_record, deduplicate_records, fingerprint, labels_for_neuralchemy, normalize_severity


class NormalizeDatasetsTests(unittest.TestCase):
    def test_benign_label_does_not_gain_attack_categories(self):
        self.assertEqual(labels_for_neuralchemy(0, "encoding"), ["benign"])

    def test_leakage_and_obfuscation_mapping(self):
        self.assertEqual(
            labels_for_neuralchemy(1, "system_extraction"),
            ["prompt_injection", "system_prompt_leakage"],
        )
        self.assertEqual(
            labels_for_neuralchemy(1, "encoding"),
            ["prompt_injection", "adversarial_obfuscation"],
        )

    def test_benign_severity_is_always_none(self):
        self.assertEqual(normalize_severity("critical", benign=True), "none")

    def test_fingerprint_normalizes_unicode_case_and_spacing(self):
        self.assertEqual(fingerprint("ＦＯＯ   Bar"), fingerprint("foo bar"))

    def test_base_record_never_has_response_field(self):
        record = base_record(
            source_id="source", revision="a" * 40, split="train", source_item_id="1",
            text="regular prompt", labels=["benign"], severity="none", license_spdx="Apache-2.0",
        )
        self.assertNotIn("response", record)

    def test_deduplication_quarantines_benign_malicious_conflict(self):
        common = dict(source_id="aegis_safety_2", revision="a" * 40, split="train",
                      text="same", severity="none", license_spdx="CC-BY-4.0")
        benign = base_record(source_item_id="1", labels=["benign"], **common)
        malicious = base_record(source_item_id="2", labels=["toxicity_harm"], **{**common, "severity": "high"})
        kept, conflicts, stats = deduplicate_records([benign, malicious])
        self.assertEqual(kept, [])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(stats["conflicting_rows_quarantined"], 2)

    def test_deduplication_merges_consistent_malicious_labels(self):
        common = dict(revision="a" * 40, split="train", text="same", severity="high", license_spdx="Apache-2.0")
        first = base_record(source_id="jackhhao_jailbreak_classification", source_item_id="1",
                            labels=["prompt_injection"], **common)
        second = base_record(source_id="neuralchemy_prompt_injection", source_item_id="2",
                             labels=["prompt_injection", "adversarial_obfuscation"], **common)
        kept, _, _ = deduplicate_records([first, second])
        self.assertEqual(kept[0]["labels"], ["adversarial_obfuscation", "prompt_injection"])


if __name__ == "__main__":
    unittest.main()
