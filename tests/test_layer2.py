import math
import tempfile
import unittest
from pathlib import Path

from echelon.contracts import Route, ThreatCategory, ThresholdPolicy
from echelon.layer2 import Layer2Classifier, StaticModelAdapter, TemperatureCalibrator


class Layer2Tests(unittest.TestCase):
    def test_static_scores_route_and_are_bounded(self):
        classifier = Layer2Classifier(StaticModelAdapter({"prompt_injection": 0.91}))
        result = classifier.analyze("untrusted prompt")
        self.assertEqual(result.route, Route.BLOCK)
        self.assertEqual(result.risk_score, 0.91)
        self.assertTrue(result.calibrated)
        self.assertEqual(result.category_scores[ThreatCategory.MALICIOUS_CODE.value], 0.0)

    def test_unknown_category_rejected(self):
        classifier = Layer2Classifier(StaticModelAdapter({"unknown": 0.5}))
        with self.assertRaisesRegex(ValueError, "unknown threat category"):
            classifier.analyze("prompt")

    def test_invalid_probability_rejected(self):
        classifier = Layer2Classifier(StaticModelAdapter({"prompt_injection": 1.1}))
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            classifier.analyze("prompt")

    def test_thresholds_are_explicit(self):
        policy = ThresholdPolicy(0.4, 0.8)
        self.assertEqual(policy.route(0.399), Route.PASS)
        self.assertEqual(policy.route(0.4), Route.ESCALATE)
        self.assertEqual(policy.route(0.8), Route.BLOCK)

    def test_temperature_calibrator_reduces_overconfidence(self):
        calibrator = TemperatureCalibrator().fit([8.0, 7.0, -7.0, -8.0], [1, 0, 1, 0])
        self.assertGreater(calibrator.temperature, 1.0)
        self.assertLess(calibrator.probability(8.0), 0.9999)

    def test_temperature_fit_rejects_bad_inputs(self):
        with self.assertRaises(ValueError):
            TemperatureCalibrator().fit([], [])
        with self.assertRaises(ValueError):
            TemperatureCalibrator().fit([1.0], [2])


if __name__ == "__main__":
    unittest.main()
