from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_keygen_tests.py")
SPEC = importlib.util.spec_from_file_location("scloud_keygen_uart", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

KeygenTestError = MODULE.KeygenTestError
KeygenVector = MODULE.KeygenVector
load_vectors = MODULE.load_vectors
receive_result = MODULE.receive_result
run_vectors = MODULE.run_vectors


SEED = bytes(range(64))
PK = bytes.fromhex("01020304")
SK = bytes.fromhex("a0b0c0d0e0")


class FakeSerial:
    def __init__(self, response_lines: list[bytes]) -> None:
        self.response_lines = response_lines
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        pass

    def readline(self) -> bytes:
        return self.response_lines.pop(0) if self.response_lines else b""

    def reset_input_buffer(self) -> None:
        pass

    def close(self) -> None:
        pass


def kat_record(count: int = 0) -> str:
    return "\n".join(
        [
            f"Count = {count}",
            "Seed_Len = 64",
            f"Seed = {SEED.hex().upper()}",
            f"PK_Len = {len(PK)}",
            f"PK = {PK.hex().upper()}",
            f"SK_Len = {len(SK)}",
            f"SK = {SK.hex().upper()}",
            "CT_Len = 1",
            "CT = 00",
            "SS_Len = 1",
            "SS = 00",
        ]
    )


class ScloudKeygenTests(unittest.TestCase):
    def test_load_vectors_reads_keygen_fields_and_ignores_later_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "KAT_KEM_Scloudplus-128-SM3-packed10.txt"
            path.write_text(f"{kat_record()}\n\n{kat_record(1)}\n", encoding="ascii")
            parameter, vectors = load_vectors(path)

        self.assertEqual(parameter, 128)
        self.assertEqual([vector.count for vector in vectors], [0, 1])
        self.assertEqual(vectors[0].seed, SEED)
        self.assertEqual(vectors[0].public_key, PK)
        self.assertEqual(vectors[0].secret_key, SK)

    def test_load_vectors_rejects_unsupported_family(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "KAT_KEM_Scloudplus-128-SHAKE-packed10.txt"
            path.write_text(kat_record(), encoding="ascii")
            with self.assertRaisesRegex(KeygenTestError, "supports only"):
                load_vectors(path)

    def test_receive_result_parses_keys_and_cycles(self) -> None:
        serial_port = FakeSerial(
            [
                b"OK PARA=128 FAMILY=SM3\r\n",
                f"PK={PK.hex()}\r\n".encode(),
                f"SK={SK.hex()}\r\n".encode(),
                b"CYCLES_ALGORITHM_TOTAL=1234\r\n",
                b"END\r\n",
            ]
        )
        public_key, secret_key, cycles = receive_result(serial_port, 128, 1.0)
        self.assertEqual(public_key, PK)
        self.assertEqual(secret_key, SK)
        self.assertEqual(cycles["CYCLES_ALGORITHM_TOTAL"], 1234)

    def test_run_vectors_sends_parameter_and_seed(self) -> None:
        serial_port = FakeSerial(
            [
                b"OK PARA=128 FAMILY=SM3\n",
                f"PK={PK.hex()}\n".encode(),
                f"SK={SK.hex()}\n".encode(),
                b"END\n",
            ]
        )
        vector = KeygenVector(0, SEED, PK, SK)
        run_vectors(serial_port, 128, [vector], 1.0)
        self.assertEqual(
            serial_port.writes,
            [f"KEYGEN 128 {SEED.hex().upper()}\n".encode("ascii")],
        )

    def test_run_vectors_stops_on_mismatch(self) -> None:
        serial_port = FakeSerial(
            [
                b"OK PARA=128 FAMILY=SM3\n",
                b"PK=ff\n",
                f"SK={SK.hex()}\n".encode(),
                b"END\n",
            ]
        )
        with self.assertRaisesRegex(KeygenTestError, "PK mismatch"):
            run_vectors(serial_port, 128, [KeygenVector(0, SEED, PK, SK)], 1.0)


if __name__ == "__main__":
    unittest.main()
