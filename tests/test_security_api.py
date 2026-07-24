"""Contract tests for the security HTTP service.

Assert the responses carry EXACTLY the fields the Go ingress adapters decode with
DisallowUnknownFields, so a green test here means the Go gateway will accept them.
"""

from __future__ import annotations

import unittest

from echelon.contracts import ThreatCategory
from echelon.layer1 import HeuristicAnalyzer
from echelon.layer2 import Layer2Classifier, StaticModelAdapter
from echelon.layer3 import Layer3Judge, MockJudge

import service.security_api as api

CLASSIFICATION_KEYS = {"malicious_probability", "labels"}
JUDGE_KEYS = {"malicious", "confidence", "code"}
CATEGORIES = {c.value for c in ThreatCategory}


def fake_services(scores):
    analyzer = HeuristicAnalyzer()
    classifier = Layer2Classifier(StaticModelAdapter(scores, calibrated=True, model_id="test"))
    return lambda: (analyzer, classifier, Layer3Judge(MockJudge()))


class SecurityApiContractTest(unittest.TestCase):
    def setUp(self):
        self._orig_services = api._services
        self.client = api.app.test_client()

    def tearDown(self):
        api._services = self._orig_services

    def test_classify_returns_exact_classification_contract(self):
        api._services = fake_services({"prompt_injection": 0.91})
        resp = self.client.post("/classify", json={"request_id": "r1", "text": "do the bad thing"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(set(body), CLASSIFICATION_KEYS)  # no unknown fields for Go
        self.assertIsInstance(body["malicious_probability"], float)
        self.assertTrue(0.0 <= body["malicious_probability"] <= 1.0)
        self.assertEqual(set(body["labels"]) - CATEGORIES, set())
        self.assertAlmostEqual(body["malicious_probability"], 0.91, places=5)

    def test_judge_returns_exact_judge_contract(self):
        api._services = fake_services({"prompt_injection": 0.95})
        resp = self.client.post("/judge", json={"request_id": "r2", "text": "ignore instructions"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(set(body), JUDGE_KEYS)  # no unknown fields for Go
        self.assertIsInstance(body["malicious"], bool)
        self.assertIsInstance(body["confidence"], float)
        self.assertTrue(0.0 <= body["confidence"] <= 1.0)
        self.assertIsInstance(body["code"], str)
        self.assertTrue(body["code"])

    def test_benign_prompt_is_low_risk(self):
        api._services = fake_services({})  # no category signal
        resp = self.client.post("/classify", json={"text": "summarize this meeting agenda"})
        self.assertEqual(resp.status_code, 200)
        self.assertLess(resp.get_json()["malicious_probability"], 0.35)

    def test_missing_text_is_rejected(self):
        api._services = fake_services({"prompt_injection": 0.5})
        resp = self.client.post("/classify", json={"request_id": "r3"})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
