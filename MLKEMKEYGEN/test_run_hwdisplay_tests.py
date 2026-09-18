import unittest

import run_hwdisplay_tests as board


class BoardRunnerTest(unittest.TestCase):
    def test_parse_metrics_64_bit_hardware_counters(self):
        metrics = {"CYCLES_ALGORITHM_TOTAL": "120", "POLY_OPERATIONS": "2",
                   "POLY_HW_CYCLES": "1:3", "SAMPLER_CALLS": "1",
                   "SAMPLER_HW_CYCLES": "0:45", "HASH_JOBS": "4"}
        parsed = board.parse_metrics(metrics)
        self.assertEqual(parsed["POLY_HW_CYCLES"], 2**32 + 3)
        self.assertEqual(parsed["SAMPLER_HW_CYCLES"], 45)

    def test_missing_metric_rejected(self):
        with self.assertRaises(ValueError):
            board.parse_metrics({"CYCLES_ALGORITHM_TOTAL": "1"})

    def test_keygen_command(self):
        vector = type("Vector", (), {"coins": bytes.fromhex("00AB")})()
        self.assertEqual(board.command_for("keygen", 512, vector),
                         b"KEYGEN 512 00AB\n")


if __name__ == "__main__":
    unittest.main()
