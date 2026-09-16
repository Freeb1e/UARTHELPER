from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("compare_sign_measurements.py")
SPEC = importlib.util.spec_from_file_location("mldsa_sign_compare", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


ComparisonError = MODULE.ComparisonError
Measurement = MODULE.Measurement


def measurement(implementation: str, cycles: int, attempts: int = 2) -> Measurement:
    return Measurement(
        parameter=44,
        implementation=implementation,
        case_number=1,
        input_id="01" * 32,
        signature_sha256="02" * 32,
        algorithm_cycles=cycles,
        attempts=attempts,
    )


class CompareSignMeasurementsTests(unittest.TestCase):
    def test_report_uses_paired_cycle_ratio(self) -> None:
        report = MODULE.build_report(
            [measurement("hardware", 100)],
            [measurement("software", 250)],
        )
        self.assertIn("2.5000x", report)
        self.assertIn("| 2 | 1 | 250.0 | 100.0 | 2.5000x |", report)

    def test_report_rejects_different_attempt_counts(self) -> None:
        with self.assertRaisesRegex(ComparisonError, "attempt count differs"):
            MODULE.build_report(
                [measurement("hardware", 100, 2)],
                [measurement("software", 250, 3)],
            )

    def test_report_rejects_different_input_sets(self) -> None:
        software = measurement("software", 250)
        software = Measurement(
            parameter=software.parameter,
            implementation=software.implementation,
            case_number=software.case_number,
            input_id="03" * 32,
            signature_sha256=software.signature_sha256,
            algorithm_cycles=software.algorithm_cycles,
            attempts=software.attempts,
        )
        with self.assertRaisesRegex(ComparisonError, "input sets differ"):
            MODULE.build_report([measurement("hardware", 100)], [software])


if __name__ == "__main__":
    unittest.main()
