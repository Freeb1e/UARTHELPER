import unittest
from types import SimpleNamespace

import run_hwdisplay_tests as board


class BoardRunnerTest(unittest.TestCase):
    def test_keygen_command(self):
        self.assertEqual(board.command_for("keygen", 44, SimpleNamespace(seed=b"\x00\xab")),
                         b"KEYGEN 44 00AB\n")

    def test_verify_command(self):
        vector = SimpleNamespace(public_key=b"\x10", message=b"\x20", signature=b"\x30")
        self.assertEqual(board.command_for("verify", 87, vector),
                         b"VERIFY 87 10 20 30\n")

    def test_counters_and_sign_implementation(self):
        metrics = {"CYCLES_ALGORITHM_TOTAL": "100", "POLY_OPERATIONS": "2",
                   "POLY_HW_CYCLES": "1:2", "SAMPLER_CALLS": "1",
                   "SAMPLER_HW_CYCLES": "0:8", "HASH_JOBS": "1"}
        self.assertEqual(board.parse_metrics("keygen", metrics)["POLY_HW_CYCLES"], 2**32 + 2)
        with self.assertRaises(ValueError):
            board.parse_metrics("sign", {**metrics, "IMPLEMENTATION": "software"})


if __name__ == "__main__":
    unittest.main()
