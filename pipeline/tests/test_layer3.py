import unittest

from echelon.contracts import LayerResult, InputStats, Route, ThresholdPolicy
from echelon.layer1 import HeuristicAnalyzer
from echelon.layer2 import Layer2Classifier, StaticModelAdapter
from echelon.layer3 import Layer3Judge, MockJudge, validate_judge_payload


class Layer3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layer1 = HeuristicAnalyzer()
        cls.layer2 = Layer2Classifier(StaticModelAdapter({"prompt_injection": 0.55}, calibrated=True))

    def test_mock_judge_returns_strict_validated_result(self):
        l1 = self.layer1.analyze("ordinary question")
        l2 = self.layer2.analyze("ordinary question")
        result = Layer3Judge(MockJudge()).analyze("ordinary question", l1, l2)
        self.assertEqual(result.route, Route.ESCALATE)
        self.assertIn("prompt_injection", result.category_scores)
        self.assertGreaterEqual(result.uncertainty, 0)
        self.assertLessEqual(result.uncertainty, 1)

    def test_judge_schema_rejects_extra_fields(self):
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            validate_judge_payload({
                "risk_score": 0.5, "category_scores": {}, "rationale_codes": ["other"],
                "uncertainty": 0.5, "recommended_route": "escalate", "raw_response": "secret",
            })

    def test_judge_schema_rejects_unknown_rationale(self):
        with self.assertRaisesRegex(ValueError, "rationale_codes"):
            validate_judge_payload({
                "risk_score": 0.5, "category_scores": {}, "rationale_codes": ["free text"],
                "uncertainty": 0.5, "recommended_route": "escalate",
            })

    def test_https_is_required_for_http_adapter(self):
        from echelon.layer3 import HttpJsonJudgeAdapter
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            HttpJsonJudgeAdapter("http://localhost", token="x", judge_id="j", revision="1")


if __name__ == "__main__":
    unittest.main()
