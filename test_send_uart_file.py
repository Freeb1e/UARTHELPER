from __future__ import annotations

import io
import os
import select
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


UARTHELPER_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(UARTHELPER_ROOT))
import send_uart_file as sender  # noqa: E402


class FakeSerial:
    def __init__(self, reads: list[bytes], short_write: bool = False):
        self.reads = iter(reads)
        self.written = bytearray()
        self.short_write = short_write

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        return len(data) - 1 if self.short_write else len(data)

    def flush(self) -> None:
        pass

    def read(self, size: int = 1) -> bytes:
        return next(self.reads, b"")

    def close(self) -> None:
        pass


class SendUartFileTests(unittest.TestCase):
    def test_fixed_paths_are_next_to_the_script(self) -> None:
        self.assertEqual(sender.INPUT_PATH, UARTHELPER_ROOT / "input.txt")
        self.assertEqual(sender.OUTPUT_PATH, UARTHELPER_ROOT / "output.log")

    def test_load_input_preserves_arbitrary_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.txt"
            expected = b"first line\r\nsecond line\n\x00\xff"
            path.write_bytes(expected)
            with mock.patch.object(sender, "INPUT_PATH", path):
                self.assertEqual(sender.load_input(), expected)

    def test_load_input_rejects_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.txt"
            path.write_bytes(b"")
            with mock.patch.object(sender, "INPUT_PATH", path):
                with self.assertRaises(sender.UartTransferError):
                    sender.load_input()

    def test_chunked_write_preserves_long_command(self) -> None:
        command = b"A" * (sender.WRITE_CHUNK_BYTES * 2 + 17) + b"\n"
        port = FakeSerial([])
        sender.write_input(port, command)
        self.assertEqual(bytes(port.written), command)

    def test_short_write_is_rejected(self) -> None:
        with self.assertRaises(sender.UartTransferError):
            sender.write_input(FakeSerial([], short_write=True), b"KEYGEN 44 AA\n")

    def test_capture_preserves_fragmented_raw_response(self) -> None:
        fragments = [
            b"OK PARA=128 FAMILY=SM3\r\nCT=AA",
            b"BB\r\nSS=CC\r\nCYCLES_ALGORITHM_TOTAL=12\r\nEN",
            b"D\r\n",
        ]
        expected = b"".join(fragments)
        output = io.BytesIO()
        echo = io.BytesIO()
        received = sender.capture_response(
            FakeSerial(fragments), output, 1.0, 0.001, echo
        )
        self.assertEqual(received, len(expected))
        self.assertEqual(output.getvalue(), expected)
        self.assertEqual(echo.getvalue(), expected)

    def test_arbitrary_error_text_is_captured_without_protocol_parsing(self) -> None:
        response = b"ERROR COMMAND\r\ncustom shell output\r\n"
        output = io.BytesIO()
        received = sender.capture_response(
            FakeSerial([response]), output, 1.0, 0.001, None
        )
        self.assertEqual(received, len(response))
        self.assertEqual(output.getvalue(), response)

    @unittest.skipUnless(os.name == "posix", "PTY integration requires POSIX")
    def test_serial_transfer_over_pty_with_long_repository_vector(self) -> None:
        try:
            import serial  # noqa: F401
        except ImportError:
            self.skipTest("pyserial is not installed")

        command_path = UARTHELPER_ROOT / "SCLOUDENCAPS/encaps_commands_128.txt"
        command = command_path.read_bytes().splitlines(keepends=True)[6]
        ct = (UARTHELPER_ROOT / "SCLOUDENCAPS/ct_ref_128.txt").read_bytes().splitlines()[6]
        ss = (UARTHELPER_ROOT / "SCLOUDENCAPS/ss_ref_128.txt").read_bytes().splitlines()[6]
        response = (
            b"OK PARA=128 FAMILY=SM3\r\nCT=" + ct + b"\r\nSS=" + ss +
            b"\r\nCPU_HZ=100000000\r\nCYCLES_ALGORITHM_TOTAL=123\r\nEND\r\n"
        )

        master, slave = os.openpty()
        slave_name = os.ttyname(slave)
        serial_port = sender.open_serial(slave_name, 115200, 5.0)
        os.close(slave)
        peer_error: list[BaseException] = []

        def emulate_board() -> None:
            try:
                received = bytearray()
                while len(received) < len(command):
                    readable, _, _ = select.select([master], [], [], 5.0)
                    if not readable:
                        raise TimeoutError("timed out waiting for the UART input")
                    received.extend(os.read(master, 65536))
                if bytes(received) != command:
                    raise AssertionError("transmitted input differs")
                for offset in range(0, len(response), 997):
                    chunk = response[offset:offset + 997]
                    written = 0
                    while written < len(chunk):
                        written += os.write(master, chunk[written:])
            except BaseException as error:
                peer_error.append(error)

        peer = threading.Thread(target=emulate_board)
        peer.start()
        try:
            output = io.BytesIO()
            sender.write_input(serial_port, command)
            received = sender.capture_response(
                serial_port, output, 5.0, 0.01, None
            )
            peer.join(timeout=10)
            self.assertFalse(peer.is_alive())
            if peer_error:
                raise peer_error[0]
            self.assertEqual(received, len(response))
            self.assertEqual(output.getvalue(), response)
        finally:
            serial_port.close()
            if peer.is_alive():
                peer.join(timeout=1)
            if master >= 0:
                os.close(master)


if __name__ == "__main__":
    unittest.main()
