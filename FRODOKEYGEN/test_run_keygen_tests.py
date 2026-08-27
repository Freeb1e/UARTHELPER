#!/usr/bin/env python3

import tempfile
import unittest
from pathlib import Path

from run_keygen_tests import (
    KeygenTestError,
    compare_results,
    load_commands,
    run_commands,
    write_results,
)


COMMAND_640 = "KEYGEN 640 0 0 " + "A5" * 64
COMMAND_976 = "KEYGEN 976 0 0 " + "5A" * 88


class FakeSerial:
    def __init__(self, responses: list[list[bytes]]) -> None:
        self.responses = responses
        self.pending: list[bytes] = []
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> int:
        if self.pending:
            raise AssertionError("next command was sent before END")
        self.writes.append(data)
        self.pending = self.responses[len(self.writes) - 1].copy()
        return len(data)

    def flush(self) -> None:
        pass

    def readline(self) -> bytes:
        line = self.pending.pop(0)
        return line

    def reset_input_buffer(self) -> None:
        self.pending.clear()


class KeygenUartTests(unittest.TestCase):
    def test_commands_are_sent_only_after_previous_end(self) -> None:
        pkh_640 = "12" * 16
        pkh_976 = "34" * 24
        serial_port = FakeSerial(
            [
                [
                    b"OK PARA=640\r\n",
                    f"PKH={pkh_640.lower()}\r\n".encode(),
                    b"END\r\n",
                ],
                [
                    b"OK PARA=976\r\n",
                    f"PKH={pkh_976}\r\n".encode(),
                    b"END\r\n",
                ],
            ]
        )

        results = run_commands(
            serial_port,
            [(COMMAND_640, 640), (COMMAND_976, 976)],
            response_timeout=1,
        )

        self.assertEqual(results, [pkh_640, pkh_976])
        self.assertEqual(
            serial_port.writes,
            [f"{COMMAND_640}\n".encode(), f"{COMMAND_976}\n".encode()],
        )

    def test_board_error_aborts_test(self) -> None:
        serial_port = FakeSerial([[b"ERROR HARDWARE DEADC0DE\r\n"]])
        with self.assertRaisesRegex(KeygenTestError, "ERROR HARDWARE"):
            run_commands(serial_port, [(COMMAND_640, 640)], response_timeout=1)

    def test_load_commands_skips_comments_and_validates_trng(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.txt"
            path.write_text(f"# vector one\n\n{COMMAND_640}\n", encoding="ascii")
            self.assertEqual(load_commands(path), [(COMMAND_640, 640)])

            path.write_text("KEYGEN 640 0 0 00\n", encoding="ascii")
            with self.assertRaisesRegex(KeygenTestError, "128 hex characters"):
                load_commands(path)

    def test_result_file_is_compared_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "pkh.txt"
            reference_path = Path(directory) / "pkh_ref.txt"
            reference_path.write_text("ABCD\n", encoding="ascii")
            write_results(result_path, ["ABCD"])
            compare_results(result_path, reference_path)

            write_results(result_path, ["DCBA"])
            with self.assertRaisesRegex(KeygenTestError, "PKH comparison failed"):
                compare_results(result_path, reference_path)


if __name__ == "__main__":
    unittest.main()
