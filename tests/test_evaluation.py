import unittest

from echelon.evaluation import binary_metrics, expected_calibration_error, select_threshold, slice_metrics


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.labels = [0, 0, 1, 1, 1, 0]
        self.scores = [0.05, 0.20, 0.65, 0.90, 0.80, 0.10]

    def test_metrics_are_computed(self):
        result = binary_metrics(self.labels, self.scores, 0.5)
        self.assertEqual((result.tp, result.tn, result.fp, result.fn), (3, 3, 0, 0))
        self.assertEqual(result.f1, 1.0)
        self.assertEqual(result.benign_fpr, 0.0)

    def test_ece_is_bounded(self):
        error = expected_calibration_error(self.labels, self.scores)
        self.assertTrue(0.0 <= error <= 1.0)

    def test_threshold_selection_honors_constraints(self):
        result = select_threshold(self.labels, self.scores, minimum_recall=1.0, maximum_benign_fpr=0.0)
        self.assertGreaterEqual(result.recall, 1.0)
        self.assertLessEqual(result.benign_fpr, 0.0)

    def test_slice_metrics(self):
        result = slice_metrics(self.labels, self.scores, ["benign", "benign", "attack", "attack", "attack", "benign"], 0.5)
        self.assertEqual(set(result), {"benign", "attack"})
        self.assertEqual(result["attack"].recall, 1.0)

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            binary_metrics([0], [1.1])
        with self.assertRaises(ValueError):
            expected_calibration_error([0], [0.5], bins=1)
