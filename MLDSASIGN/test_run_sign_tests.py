from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_sign_tests.py")
SPEC = importlib.util.spec_from_file_location("mldsa_sign_uart", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SignInput = MODULE.SignInput
SignTestError = MODULE.SignTestError
SignVector = MODULE.SignVector


PROFILE_LINES = [
    b"SIGN_ATTEMPTS=1\n",
    b"SIGN_ATTEMPT_CYCLES=80000\n",
    b"SIGN_SUCCESS_CYCLES=80000\n",
    b"SIGN_REJECT_Z=0\n",
    b"SIGN_REJECT_Z_CYCLES=0\n",
    b"SIGN_REJECT_W0=0\n",
    b"SIGN_REJECT_W0_CYCLES=0\n",
    b"SIGN_REJECT_H=0\n",
    b"SIGN_REJECT_H_CYCLES=0\n",
    b"SIGN_REJECT_OMEGA=0\n",
    b"SIGN_REJECT_OMEGA_CYCLES=0\n",
]


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


class MldsaSignTests(unittest.TestCase):
    def test_firmware_requires_sign_sampler_masks(self) -> None:
        source = (
            MODULE.PROJECT_ROOT
            / "e203_hbirdv2/scripts/BOARDSW/kd_mldsa_sign/main.c"
        ).read_text(encoding="ascii")
        for mask in ("0x148u", "0x288u", "0x488u"):
            self.assertIn(mask, source)

    def test_load_inputs_accepts_comments(self) -> None:
        value = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            line = f"SIGN 44 {value.hex()} {value.hex()} {value.hex()}"
            path.write_text(f"# test\n{line}\n\n{line}\n", encoding="ascii")
            loaded = MODULE.load_inputs(path, 44)
        self.assertEqual(loaded, [SignInput(value, value, value)] * 2)

    def test_load_inputs_rejects_parameter_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            path.write_text(
                f"SIGN 65 {'00' * 32} {'11' * 32} {'22' * 32}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(SignTestError, "does not match"):
                MODULE.load_inputs(path, 44)

    def test_generated_benchmark_inputs_are_deterministic(self) -> None:
        first = MODULE.generate_benchmark_inputs(65, 3)
        self.assertEqual(first, MODULE.generate_benchmark_inputs(65, 3))
        self.assertEqual(len(first), 3)
        self.assertNotEqual(first[0], first[1])
        self.assertEqual(first[2], MODULE.generate_benchmark_inputs(65, 1, 2)[0])

    def test_software_reference_has_expected_sizes(self) -> None:
        source = SignInput(bytes(range(32)), bytes(range(32, 64)), bytes(32))
        for parameter in MODULE.SUPPORTED_PARAMETERS:
            with self.subTest(parameter=parameter):
                vector = MODULE.build_golden(parameter, [source])[0]
                self.assertEqual(
                    len(vector.secret_key), MODULE.SECRET_KEY_BYTES[parameter]
                )
                self.assertEqual(
                    len(vector.signature), MODULE.SIGNATURE_BYTES[parameter]
                )

    def test_receive_result_parses_signature_and_metrics(self) -> None:
        serial_port = FakeSerial([
            b"OK PARA=44\r\n", b"SIG=0102\r\n",
            b"CYCLES_ALGORITHM_TOTAL=1234\r\n", b"HASH_JOBS=10\r\n",
            b"END\r\n",
        ])
        signature, metrics = MODULE.receive_result(serial_port, 44, 1.0)
        self.assertEqual(signature, b"\x01\x02")
        self.assertEqual(metrics["HASH_JOBS"], "10")

    def test_run_vectors_sends_secret_key_message_and_random(self) -> None:
        source = SignInput(bytes(32), bytes(range(32)), bytes([0xA5]) * 32)
        signature = bytes([0x5A]) * MODULE.SIGNATURE_BYTES[44]
        vector = SignVector(source, b"\x01\x02", signature)
        serial_port = FakeSerial([
            b"OK PARA=44\n", f"SIG={signature.hex()}\n".encode("ascii"),
            b"CYCLES_ALGORITHM_TOTAL=100000\n", *PROFILE_LINES, b"END\n",
        ])
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.run_vectors(serial_port, 44, [vector], 1.0, 100.0)
        expected = (
            f"SIGN 44 0102 {source.message.hex().upper()} "
            f"{source.sign_random.hex().upper()}\n"
        ).encode("ascii")
        self.assertEqual(serial_port.writes, [expected])
        self.assertIn("1.000000 ms", output.getvalue())

    def test_profile_summary_uses_theoretical_attempts(self) -> None:
        measurement = MODULE.SignMeasurement(
            algorithm_cycles=1000,
            attempts=3,
            attempt_cycles=700,
            success_cycles=300,
            reject_z=1,
            reject_z_cycles=150,
            reject_w0=1,
            reject_w0_cycles=250,
            reject_h=0,
            reject_h_cycles=0,
            reject_omega=0,
            reject_omega_cycles=0,
        )
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.print_profile_summary(44, [measurement])
        self.assertIn("THEORETICAL_MEAN_ATTEMPTS=4.25", output.getvalue())
        self.assertIn("THEORETICAL_MEAN_TOTAL_CYCLES=1250.000", output.getvalue())

    def test_run_vectors_reports_signature_mismatch(self) -> None:
        source = SignInput(bytes(32), bytes(32), bytes(32))
        expected = bytes(MODULE.SIGNATURE_BYTES[44])
        actual = b"\xff" + expected[1:]
        vector = SignVector(source, b"\x01", expected)
        serial_port = FakeSerial([
            b"OK PARA=44\n", f"SIG={actual.hex()}\n".encode("ascii"), b"END\n",
        ])
        with self.assertRaisesRegex(SignTestError, "mismatch at byte 0"):
            MODULE.run_vectors(serial_port, 44, [vector], 1.0)


if __name__ == "__main__":
    unittest.main()
