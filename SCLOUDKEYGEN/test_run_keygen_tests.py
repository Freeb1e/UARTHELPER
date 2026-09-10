from __future__ import annotations

import importlib.util
import io
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch


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
COMMAND = f"KEYGEN 128 {(SEED + SEED).hex().upper()}\n".encode("ascii")


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
    def test_run_vectors_displays_stage_cycles_and_time(self) -> None:
        serial_port = FakeSerial([
            b"OK PARA=128 FAMILY=SM3\n",
            f"PK={PK.hex()}\n".encode(),
            f"SK={SK.hex()}\n".encode(),
            b"CYCLES_COMPACT_B=100000\n",
            b"CYCLES_PACK_PK=200000\n",
            b"CYCLES_ALGORITHM_TOTAL=310000\n",
            b"END\n",
        ])
        output = io.StringIO()
        with redirect_stdout(output):
            run_vectors(serial_port, 128, [KeygenVector(0, SEED, PK, SK)], [COMMAND], 1.0, 100.0)
        report = output.getvalue()
        self.assertRegex(report, r"COMPACT_B\s+100000\s+1\.000000")
        self.assertRegex(report, r"PACK_PK\s+200000\s+2\.000000")
        self.assertRegex(report, r"ALGORITHM_TOTAL\s+310000\s+3\.100000")
        self.assertIn("PASS PK=", report)

    def test_cycle_report_without_frequency_shows_only_cycles(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.print_cycle_report({"CYCLES_PACK_PK": 12345}, None)
        self.assertRegex(output.getvalue(), r"PACK_PK\s+12345")
        self.assertNotIn("MHz", output.getvalue())

    def test_invalid_cpu_frequency_does_not_open_serial(self) -> None:
        for frequency in ("0", "-1", "nan", "inf"):
            with self.subTest(frequency=frequency), patch.object(MODULE, "open_serial") as port:
                self.assertEqual(MODULE.main(["--port", "unused", "--cpu-mhz", frequency]), 1)
                port.assert_not_called()

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

    def test_run_vectors_sends_parameter_and_random_inputs(self) -> None:
        serial_port = FakeSerial(
            [
                b"OK PARA=128 FAMILY=SM3\n",
                f"PK={PK.hex()}\n".encode(),
                f"SK={SK.hex()}\n".encode(),
                b"END\n",
            ]
        )
        vector = KeygenVector(0, SEED, PK, SK)
        run_vectors(serial_port, 128, [vector], [COMMAND], 1.0)
        self.assertEqual(
            serial_port.writes,
            [COMMAND],
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
            run_vectors(serial_port, 128, [KeygenVector(0, SEED, PK, SK)], [COMMAND], 1.0)

    def test_official_drng_matches_all_supported_kat_random_inputs(self) -> None:
        for parameter in (128, 192, 256):
            path = MODULE.DEFAULT_VECTORS.with_name(
                f"KAT_KEM_Scloudplus-{parameter}-SM3-packed10.txt"
            )
            _, vectors = load_vectors(path)
            commands = MODULE.build_commands(parameter, vectors)
            for vector, command in zip(vectors, commands):
                with self.subTest(parameter=parameter, count=vector.count):
                    fields = command.decode("ascii").split()
                    self.assertEqual(fields[:2], ["KEYGEN", str(parameter)])
                    inputs = bytes.fromhex(fields[2])
                    self.assertEqual(len(inputs), 128)
                    self.assertEqual(inputs[:64], vector.secret_key[-64:])
                    seed_a = hashlib.new("sm3", b"F" + inputs[64:] + b"\0\0\0\1").digest()[:16]
                    self.assertEqual(seed_a, vector.public_key[-16:])

    def test_export_commands_without_opening_serial(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(MODULE, "open_serial") as port:
            path = Path(directory) / "commands.txt"
            self.assertEqual(MODULE.main(["--commands-out", str(path)]), 0)
            commands = path.read_bytes().splitlines()
            self.assertEqual(len(commands), 10)
            for command in commands:
                fields = command.split()
                self.assertEqual(fields[:2], [b"KEYGEN", b"128"])
                self.assertEqual(len(bytes.fromhex(fields[2].decode())), 128)
            port.assert_not_called()


if __name__ == "__main__":
    unittest.main()
