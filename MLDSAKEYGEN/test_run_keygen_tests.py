from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_keygen_tests.py")
SPEC = importlib.util.spec_from_file_location("mldsa_keygen_uart", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

KeygenTestError = MODULE.KeygenTestError
KeygenVector = MODULE.KeygenVector


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


class MldsaKeygenTests(unittest.TestCase):
    def test_firmware_requires_keygen_sampler_masks(self) -> None:
        source = (
            MODULE.PROJECT_ROOT
            / "e203_hbirdv2/scripts/BOARDSW/kd_mldsa_keygen/main.c"
        ).read_text(encoding="ascii")
        self.assertIn("DILITHIUM_MODE == 3 ? 0x28u : 0x18u", source)

    def test_load_seeds_accepts_comments(self) -> None:
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            path.write_text(
                f"# test\nKEYGEN 44 {seed.hex()}\n\nKEYGEN 44 {seed.hex()}\n",
                encoding="ascii",
            )
            loaded = MODULE.load_seeds(path, 44)
        self.assertEqual(loaded, [seed, seed])

    def test_load_seeds_rejects_parameter_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            path.write_text(f"KEYGEN 65 {'00' * 32}\n", encoding="ascii")
            with self.assertRaisesRegex(KeygenTestError, "does not match"):
                MODULE.load_seeds(path, 44)

    def test_software_reference_has_expected_key_sizes(self) -> None:
        for parameter, sizes in MODULE.KEY_SIZES.items():
            with self.subTest(parameter=parameter):
                vector = MODULE.build_golden(parameter, [bytes(range(32))])[0]
                self.assertEqual(len(vector.public_key), sizes[0])
                self.assertEqual(len(vector.secret_key), sizes[1])

    def test_receive_result_parses_keys_and_metrics(self) -> None:
        serial_port = FakeSerial([
            b"OK PARA=44\r\n", b"PK=0102\r\n", b"SK=a0b0\r\n",
            b"CYCLES_ALGORITHM_TOTAL=1234\r\n", b"HASH_JOBS=10\r\n",
            b"END\r\n",
        ])
        public_key, secret_key, metrics = MODULE.receive_result(
            serial_port, 44, 1.0
        )
        self.assertEqual(public_key, b"\x01\x02")
        self.assertEqual(secret_key, b"\xa0\xb0")
        self.assertEqual(metrics["HASH_JOBS"], "10")

    def test_run_vectors_sends_command_and_compares_keys(self) -> None:
        vector = KeygenVector(bytes(range(32)), b"\x01\x02", b"\xa0\xb0")
        serial_port = FakeSerial([
            b"OK PARA=44\n", b"PK=0102\n", b"SK=a0b0\n",
            b"CYCLES_ALGORITHM_TOTAL=100000\n", b"END\n",
        ])
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.run_vectors(serial_port, 44, [vector], 1.0, 100.0)
        expected = f"KEYGEN 44 {vector.seed.hex().upper()}\n".encode("ascii")
        self.assertEqual(serial_port.writes, [expected])
        self.assertIn("1.000000 ms", output.getvalue())

    def test_run_vectors_reports_key_mismatch(self) -> None:
        vector = KeygenVector(bytes(32), b"\x01", b"\x02")
        serial_port = FakeSerial([
            b"OK PARA=44\n", b"PK=ff\n", b"SK=02\n", b"END\n",
        ])
        with self.assertRaisesRegex(KeygenTestError, "PK mismatch"):
            MODULE.run_vectors(serial_port, 44, [vector], 1.0)


if __name__ == "__main__":
    unittest.main()
