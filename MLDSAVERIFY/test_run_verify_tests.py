from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_verify_tests.py")
SPEC = importlib.util.spec_from_file_location("mldsa_verify_uart", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VerifyInput = MODULE.VerifyInput
VerifyTestError = MODULE.VerifyTestError
VerifyVector = MODULE.VerifyVector


class FakeSerial:
    def __init__(self, lines: list[bytes]) -> None:
        self.lines = lines
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        pass

    def readline(self) -> bytes:
        return self.lines.pop(0) if self.lines else b""

    def reset_input_buffer(self) -> None:
        pass

    def close(self) -> None:
        pass


class MldsaVerifyTests(unittest.TestCase):
    def test_firmware_requires_verify_sampler_masks(self) -> None:
        source = (
            MODULE.PROJECT_ROOT
            / "e203_hbirdv2/scripts/BOARDSW/kd_mldsa_verify/main.c"
        ).read_text(encoding="ascii")
        for mask in ("0x108u", "0x208u", "0x408u"):
            self.assertIn(mask, source)

    def test_load_inputs_accepts_comments(self) -> None:
        value = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            line = f"VERIFY 44 {value.hex()} {value.hex()} {value.hex()}"
            path.write_text(f"# test\n{line}\n\n{line}\n", encoding="ascii")
            loaded = MODULE.load_inputs(path, 44)
        self.assertEqual(loaded, [VerifyInput(value, value, value)] * 2)

    def test_load_inputs_rejects_parameter_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            path.write_text(
                f"VERIFY 65 {'00' * 32} {'11' * 32} {'22' * 32}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(VerifyTestError, "does not match"):
                MODULE.load_inputs(path, 44)

    def test_software_reference_builds_valid_and_tampered_cases(self) -> None:
        source = VerifyInput(bytes(range(32)), bytes(range(32, 64)), bytes(32))
        for parameter in MODULE.SUPPORTED_PARAMETERS:
            with self.subTest(parameter=parameter):
                vectors = MODULE.build_golden(parameter, [source])
                self.assertEqual(len(vectors), 2)
                self.assertTrue(vectors[0].expected_valid)
                self.assertFalse(vectors[1].expected_valid)
                self.assertEqual(vectors[0].public_key, vectors[1].public_key)
                self.assertEqual(vectors[0].signature[0] ^ 1, vectors[1].signature[0])

    def test_receive_result_parses_invalid_and_metrics(self) -> None:
        serial_port = FakeSerial([
            b"OK PARA=44\r\n", b"VALID=0\r\n",
            b"CYCLES_ALGORITHM_TOTAL=1234\r\n", b"HASH_JOBS=10\r\n",
            b"END\r\n",
        ])
        valid, metrics = MODULE.receive_result(serial_port, 44, 1.0)
        self.assertFalse(valid)
        self.assertEqual(metrics["HASH_JOBS"], "10")

    def test_run_vectors_sends_complete_inputs(self) -> None:
        vector = VerifyVector("valid", b"\x01\x02", bytes(32), b"\xa0\xb0", True)
        serial_port = FakeSerial([
            b"OK PARA=44\n", b"VALID=1\n",
            b"CYCLES_ALGORITHM_TOTAL=100000\n", b"END\n",
        ])
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.run_vectors(serial_port, 44, [vector], 1.0, 100.0)
        expected = (
            f"VERIFY 44 0102 {bytes(32).hex().upper()} A0B0\n"
        ).encode("ascii")
        self.assertEqual(serial_port.writes, [expected])
        self.assertIn("PASS VALID=1", output.getvalue())
        self.assertIn("1.000000 ms", output.getvalue())

    def test_run_vectors_reports_decision_mismatch(self) -> None:
        vector = VerifyVector("tampered", b"\x01", bytes(32), b"\x02", False)
        serial_port = FakeSerial([
            b"OK PARA=44\n", b"VALID=1\n", b"END\n",
        ])
        with self.assertRaisesRegex(VerifyTestError, "expected 0"):
            MODULE.run_vectors(serial_port, 44, [vector], 1.0)


if __name__ == "__main__":
    unittest.main()
