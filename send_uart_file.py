#!/usr/bin/env python3
"""Send the fixed input file verbatim and capture UART output to a fixed log."""

from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path
from typing import BinaryIO, Protocol, Sequence


DEFAULT_BAUD_RATE = 115200
DEFAULT_RESPONSE_TIMEOUT = 300.0
DEFAULT_IDLE_TIMEOUT = 2.0
WRITE_CHUNK_BYTES = 4096
SCRIPT_DIR = Path(__file__).resolve().parent
INPUT_PATH = SCRIPT_DIR / "input.txt"
OUTPUT_PATH = SCRIPT_DIR / "output.log"


class UartTransferError(RuntimeError):
    """Raised when the command or serial transfer is invalid."""


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...
    def flush(self) -> None: ...
    def read(self, size: int = 1) -> bytes: ...
    def close(self) -> None: ...


def load_input() -> bytes:
    try:
        content = INPUT_PATH.read_bytes()
    except OSError as error:
        raise UartTransferError(f"cannot read fixed input file {INPUT_PATH}: {error}") from error
    if not content:
        raise UartTransferError(f"fixed input file is empty: {INPUT_PATH}")
    return content


def write_input(serial_port: SerialPort, payload: bytes) -> None:
    for offset in range(0, len(payload), WRITE_CHUNK_BYTES):
        chunk = payload[offset:offset + WRITE_CHUNK_BYTES]
        written = serial_port.write(chunk)
        if written != len(chunk):
            raise UartTransferError(
                f"UART short write at byte {offset}: wrote {written} of {len(chunk)} bytes"
            )
    serial_port.flush()


def capture_response(
    serial_port: SerialPort,
    output: BinaryIO,
    response_timeout: float,
    idle_timeout: float,
    echo: BinaryIO | None,
) -> int:
    deadline = time.monotonic() + response_timeout
    received = 0

    while time.monotonic() < deadline:
        chunk = serial_port.read(4096)
        if not chunk:
            continue
        deadline = time.monotonic() + idle_timeout
        output.write(chunk)
        output.flush()
        if echo is not None:
            echo.write(chunk)
            echo.flush()
        received += len(chunk)

    if received == 0:
        raise UartTransferError(f"no UART data received for {response_timeout:g} seconds")
    return received


def open_serial(port: str, baud_rate: int, timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise UartTransferError(
            "pyserial is not installed; run: python3 -m pip install "
            "-r UARTHELPER/SCLOUDKEYGEN/requirements.txt"
        ) from error

    try:
        return serial.Serial(
            port=port,
            baudrate=baud_rate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=min(0.2, timeout),
            write_timeout=timeout,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
        )
    except serial.SerialException as error:
        raise UartTransferError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="serial device, e.g. /dev/ttyUSB2")
    parser.add_argument("--baud-rate", type=int, default=DEFAULT_BAUD_RATE)
    parser.add_argument(
        "--response-timeout", type=float, default=DEFAULT_RESPONSE_TIMEOUT,
        help="maximum seconds to wait for the first received byte (default: 300)",
    )
    parser.add_argument(
        "--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT,
        help="finish after this many seconds without more received data (default: 2)",
    )
    parser.add_argument(
        "--startup-delay", type=float, default=1.0,
        help="seconds to wait after opening the port before sending (default: 1)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="write the response only to the log instead of also echoing it",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    serial_port: SerialPort | None = None
    try:
        args = parse_args(argv)
        if args.baud_rate <= 0:
            raise UartTransferError("baud-rate must be positive")
        if not math.isfinite(args.response_timeout) or args.response_timeout <= 0:
            raise UartTransferError("response-timeout must be finite and positive")
        if not math.isfinite(args.idle_timeout) or args.idle_timeout <= 0:
            raise UartTransferError("idle-timeout must be finite and positive")
        if not math.isfinite(args.startup_delay) or args.startup_delay < 0:
            raise UartTransferError("startup-delay must be finite and nonnegative")
        payload = load_input()
        serial_port = open_serial(args.port, args.baud_rate, args.response_timeout)
        if args.startup_delay:
            time.sleep(args.startup_delay)

        print(
            f"Sending {len(payload)} bytes from {INPUT_PATH} to {args.port} "
            f"at {args.baud_rate} baud",
            file=sys.stderr,
        )
        with OUTPUT_PATH.open("wb") as output:
            write_input(serial_port, payload)
            received = capture_response(
                serial_port,
                output,
                args.response_timeout,
                args.idle_timeout,
                None if args.quiet else sys.stdout.buffer,
            )
        print(
            f"Received {received} bytes; raw response saved to {OUTPUT_PATH}",
            file=sys.stderr,
        )
        return 0
    except (UartTransferError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    finally:
        if serial_port is not None:
            serial_port.close()


if __name__ == "__main__":
    raise SystemExit(main())
