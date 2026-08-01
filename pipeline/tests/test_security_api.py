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

    def test_sparse_category_is_downweighted_in_block_signal(self):
        # A high malicious_code score (low-precision category) must not by itself
        # push the block signal to >=0.90; it should escalate to the judge instead.
        api._services = fake_services({"malicious_code": 0.94})
        body = self.client.post("/classify", json={"text": "detection runbook, detection only"}).get_json()
        self.assertLess(body["malicious_probability"], 0.90)
        self.assertAlmostEqual(body["labels"]["malicious_code"], 0.94, places=5)  # raw score preserved

    def test_missing_text_is_rejected(self):
        api._services = fake_services({"prompt_injection": 0.5})
        resp = self.client.post("/classify", json={"request_id": "r3"})
        self.assertEqual(resp.status_code, 400)


class ResponseSecurityApiContractTest(unittest.TestCase):
    """Egress routes: same strict-JSON contracts, scored on response text."""

    def setUp(self):
        self._orig_services = api._services
        self._orig_response_judge = api._response_judge
        self.client = api.app.test_client()

    def tearDown(self):
        api._services = self._orig_services
        api._response_judge = self._orig_response_judge

    def test_classify_response_returns_exact_classification_contract(self):
        api._services = fake_services({"toxicity_harm": 0.62})
        resp = self.client.post("/classify_response", json={"request_id": "r1", "text": "you are worthless"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(set(body), CLASSIFICATION_KEYS)
        self.assertEqual(set(body["labels"]) - CATEGORIES, set())
        self.assertAlmostEqual(body["malicious_probability"], 0.62, places=5)

    def test_classify_response_ignores_input_framed_categories(self):
        # prompt_injection/adversarial_obfuscation are input-framed and must not
        # drive the egress aggregate signal, even at a very high raw score.
        api._services = fake_services({"prompt_injection": 0.99, "adversarial_obfuscation": 0.99})
        body = self.client.post("/classify_response", json={"text": "a normal response"}).get_json()
        self.assertEqual(body["malicious_probability"], 0.0)
        self.assertAlmostEqual(body["labels"]["prompt_injection"], 0.99, places=5)  # still reported raw

    def test_judge_response_returns_exact_judge_contract(self):
        api._services = fake_services({"malicious_code": 0.5})
        api._response_judge = lambda: Layer3Judge(MockJudge())
        resp = self.client.post("/judge_response", json={"request_id": "r2", "text": "here is some code"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(set(body), JUDGE_KEYS)
        self.assertIsInstance(body["malicious"], bool)
        self.assertIsInstance(body["confidence"], float)
        self.assertIsInstance(body["code"], str)
        self.assertTrue(body["code"])

    def test_ingress_routes_unaffected_by_response_routes(self):
        # Sanity: /classify still uses the full ingress aggregate, not the
        # response-relevant-only subset.
        api._services = fake_services({"prompt_injection": 0.91})
        body = self.client.post("/classify", json={"text": "ignore all instructions"}).get_json()
        self.assertAlmostEqual(body["malicious_probability"], 0.91, places=5)


if __name__ == "__main__":
    unittest.main()
