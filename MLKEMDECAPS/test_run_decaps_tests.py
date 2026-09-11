from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_decaps_tests.py")
SPEC = importlib.util.spec_from_file_location("mlkem_decaps_uart", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

DecapsInput = MODULE.DecapsInput
DecapsTestError = MODULE.DecapsTestError
DecapsVector = MODULE.DecapsVector


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


class MlkemDecapsTests(unittest.TestCase):
    def test_firmware_requires_decaps_sampler_masks_and_all_poly_operations(self) -> None:
        source = (
            MODULE.PROJECT_ROOT
            / "e203_hbirdv2/scripts/BOARDSW/kd_mlkem_decaps/main.c"
        ).read_text(encoding="ascii")
        self.assertIn("KYBER_K == 2 ? 0x7u : 0x3u", source)
        self.assertIn("poly->ntt_calls == 0u", source)
        self.assertIn("poly->intt_calls == 0u", source)
        self.assertIn("poly->pointwise_calls == 0u", source)

    def test_load_inputs_accepts_comments(self) -> None:
        keygen_coins = bytes(range(64))
        encaps_coins = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inputs.txt"
            path.write_text(
                f"# test\nDECAPS_INPUT 512 {keygen_coins.hex()} {encaps_coins.hex()}\n",
                encoding="ascii",
            )
            loaded = MODULE.load_inputs(path, 512)
        self.assertEqual(loaded, [DecapsInput(keygen_coins, encaps_coins)])

    def test_load_inputs_rejects_parameter_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inputs.txt"
            path.write_text(
                f"DECAPS_INPUT 768 {'00' * 64} {'00' * 32}\n", encoding="ascii"
            )
            with self.assertRaisesRegex(DecapsTestError, "does not match"):
                MODULE.load_inputs(path, 512)

    def test_software_reference_builds_valid_and_tampered_vectors(self) -> None:
        test_input = DecapsInput(bytes(range(64)), bytes(range(32)))
        for parameter, sizes in MODULE.OBJECT_SIZES.items():
            with self.subTest(parameter=parameter):
                vectors = MODULE.build_golden(parameter, [test_input])
                self.assertEqual([vector.kind for vector in vectors], ["valid", "tampered"])
                self.assertEqual(len(vectors[0].secret_key), sizes[0])
                self.assertEqual(len(vectors[0].ciphertext), sizes[1])
                self.assertEqual(len(vectors[0].shared_secret), sizes[2])
                self.assertNotEqual(vectors[0].ciphertext, vectors[1].ciphertext)
                self.assertNotEqual(vectors[0].shared_secret, vectors[1].shared_secret)

    def test_receive_result_parses_secret_and_metrics(self) -> None:
        serial_port = FakeSerial([
            b"OK PARA=512\r\n",
            b"SS=a0b0\r\n",
            b"CYCLES_ALGORITHM_TOTAL=1234\r\n",
            b"HASH_JOBS=15\r\n",
            b"END\r\n",
        ])
        shared_secret, metrics = MODULE.receive_result(serial_port, 512, 1.0)
        self.assertEqual(shared_secret, b"\xa0\xb0")
        self.assertEqual(metrics["HASH_JOBS"], "15")

    def test_run_vectors_sends_command_and_compares_secret(self) -> None:
        vector = DecapsVector("valid", b"\x10\x20", b"\x01\x02", b"\xa0\xb0")
        serial_port = FakeSerial([
            b"OK PARA=512\n", b"SS=a0b0\n",
            b"CYCLES_ALGORITHM_TOTAL=100000\n", b"END\n",
        ])
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.run_vectors(serial_port, 512, [vector], 1.0, 100.0)
        expected = (
            f"DECAPS 512 {vector.secret_key.hex().upper()} "
            f"{vector.ciphertext.hex().upper()}\n"
        ).encode("ascii")
        self.assertEqual(serial_port.writes, [expected])
        self.assertIn("VALID", output.getvalue())
        self.assertIn("1.000000 ms", output.getvalue())

    def test_run_vectors_reports_secret_mismatch(self) -> None:
        vector = DecapsVector("tampered", b"\x10", b"\x01", b"\x02")
        serial_port = FakeSerial([
            b"OK PARA=512\n", b"SS=ff\n", b"END\n",
        ])
        with self.assertRaisesRegex(DecapsTestError, "SS mismatch"):
            MODULE.run_vectors(serial_port, 512, [vector], 1.0)


if __name__ == "__main__":
    unittest.main()
