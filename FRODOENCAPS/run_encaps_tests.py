#!/usr/bin/env python3
"""Run Frodo Encaps test vectors through the board UART protocol."""

from __future__ import annotations

import argparse
import difflib
import sys
import time
from pathlib import Path
from typing import Protocol, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PK_HEX_LENGTHS = {"640": 19232, "976": 31264, "1344": 43040}
TRNG_HEX_LENGTHS = {"640": 96, "976": 144, "1344": 192}
SS_HEX_LENGTHS = {"640": 32, "976": 48, "1344": 64}


class EncapsTestError(RuntimeError):
    """Raised when input, UART communication, or a board response is invalid."""


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...

    def readline(self) -> bytes: ...

    def reset_input_buffer(self) -> None: ...


def validate_hex_field(
    value: str, expected_length: int, field: str, parameter: str, line_number: int
) -> None:
    if len(value) != expected_length:
        raise EncapsTestError(
            f"commands line {line_number}: Frodo-{parameter} {field} must contain "
            f"{expected_length} hex characters, got {len(value)}"
        )
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise EncapsTestError(
            f"commands line {line_number}: {field} contains non-hex characters"
        ) from error


def parse_command(line: str, line_number: int) -> tuple[str, int]:
    fields = line.split()
    if len(fields) != 6 or fields[0] != "ENCAPS":
        raise EncapsTestError(
            f"commands line {line_number}: expected "
            "ENCAPS <parameter> <cycles> <print_ct> <pk_hex> <trng_hex>"
        )

    parameter, cycles, print_ct, pk_hex, trng_hex = fields[1:]
    if parameter not in PK_HEX_LENGTHS:
        raise EncapsTestError(
            f"commands line {line_number}: unsupported parameter {parameter!r}"
        )
    if cycles not in {"0", "1"}:
        raise EncapsTestError(
            f"commands line {line_number}: cycles must be 0 or 1"
        )
    if print_ct not in {"0", "1"}:
        raise EncapsTestError(
            f"commands line {line_number}: print_ct must be 0 or 1"
        )
    validate_hex_field(
        pk_hex, PK_HEX_LENGTHS[parameter], "PK", parameter, line_number
    )
    validate_hex_field(
        trng_hex, TRNG_HEX_LENGTHS[parameter], "TRNG", parameter, line_number
    )

    return " ".join(fields), int(parameter)


def load_commands(path: Path) -> list[tuple[str, int]]:
    commands: list[tuple[str, int]] = []
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise EncapsTestError(f"cannot read commands file {path}: {error}") from error

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        commands.append(parse_command(line, line_number))

    if not commands:
        raise EncapsTestError(f"commands file {path} contains no test cases")
    return commands


def receive_ss(serial_port: SerialPort, parameter: int, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    saw_ok = False
    shared_secret: str | None = None

    while time.monotonic() < deadline:
        raw_line = serial_port.readline()
        if not raw_line:
            continue
        try:
            line = raw_line.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise EncapsTestError("board returned non-ASCII UART data") from error
        if not line:
            continue

        print(f"  RX {line}")
        if line.startswith("ERROR"):
            raise EncapsTestError(f"board rejected Frodo-{parameter} request: {line}")
        if line == f"OK PARA={parameter}":
            saw_ok = True
        elif line.startswith("SS="):
            if shared_secret is not None:
                raise EncapsTestError("board returned more than one SS line")
            shared_secret = line.removeprefix("SS=").upper()
        elif line == "END":
            if not saw_ok:
                raise EncapsTestError("board response ended without the expected OK line")
            if shared_secret is None:
                raise EncapsTestError("board response ended without an SS line")
            expected_length = SS_HEX_LENGTHS[str(parameter)]
            if len(shared_secret) != expected_length:
                raise EncapsTestError(
                    f"Frodo-{parameter} SS must contain {expected_length} hex "
                    f"characters, got {len(shared_secret)}"
                )
            try:
                bytes.fromhex(shared_secret)
            except ValueError as error:
                raise EncapsTestError("board SS contains non-hex characters") from error
            return shared_secret

    raise EncapsTestError(f"timed out after {timeout:g}s waiting for END")


def run_commands(
    serial_port: SerialPort,
    commands: Sequence[tuple[str, int]],
    response_timeout: float,
) -> list[str]:
    results: list[str] = []
    total = len(commands)

    for index, (command, parameter) in enumerate(commands, start=1):
        payload = f"{command}\n".encode("ascii")
        print(f"[{index}/{total}] TX ENCAPS {parameter} ({len(payload)} bytes)")
        written = serial_port.write(payload)
        if written != len(payload):
            raise EncapsTestError(
                f"UART short write: sent {written} of {len(payload)} bytes"
            )
        serial_port.flush()
        results.append(receive_ss(serial_port, parameter, response_timeout))

    return results


def write_results(path: Path, results: Sequence[str]) -> None:
    content = "".join(f"{shared_secret}\n" for shared_secret in results)
    try:
        path.write_text(content, encoding="ascii", newline="\n")
    except OSError as error:
        raise EncapsTestError(f"cannot write result file {path}: {error}") from error


def compare_results(result_path: Path, reference_path: Path) -> None:
    try:
        actual_bytes = result_path.read_bytes()
        expected_bytes = reference_path.read_bytes()
    except OSError as error:
        raise EncapsTestError(f"cannot compare result files: {error}") from error
    if actual_bytes == expected_bytes:
        return

    try:
        expected = reference_path.read_text(encoding="ascii").splitlines(keepends=True)
        actual = result_path.read_text(encoding="ascii").splitlines(keepends=True)
    except (OSError, UnicodeError) as error:
        raise EncapsTestError(f"cannot show result difference: {error}") from error
    difference = "".join(
        difflib.unified_diff(
            expected,
            actual,
            fromfile=str(reference_path),
            tofile=str(result_path),
        )
    )
    raise EncapsTestError(f"SS comparison failed:\n{difference.rstrip()}")


def open_serial(port: str, baud_rate: int, response_timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise EncapsTestError(
            "pyserial is not installed; run "
            f"{sys.executable} -m pip install -r {SCRIPT_DIR / 'requirements.txt'}"
        ) from error

    try:
        return serial.Serial(
            port=port,
            baudrate=baud_rate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=min(0.2, response_timeout),
            write_timeout=response_timeout,
        )
    except serial.SerialException as error:
        raise EncapsTestError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send Frodo Encaps commands sequentially and compare SS results."
    )
    parser.add_argument("--port", required=True, help="serial device, e.g. /dev/ttyUSB0")
    parser.add_argument("--baud-rate", type=int, default=115200)
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="maximum seconds to wait for each response (default: 30)",
    )
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=1.0,
        help="seconds to let the board settle after opening the port (default: 1)",
    )
    parser.add_argument(
        "--commands",
        type=Path,
        default=SCRIPT_DIR / "encaps_commands.txt",
    )
    parser.add_argument(
        "--reference",
        type=Path,
        default=SCRIPT_DIR / "ss.txt",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=SCRIPT_DIR / "ss_board.txt",
    )
    args = parser.parse_args(argv)
    if args.baud_rate <= 0:
        parser.error("--baud-rate must be greater than zero")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.startup_delay < 0:
        parser.error("--startup-delay cannot be negative")
    if args.output.resolve() == args.reference.resolve():
        parser.error("--output and --reference must be different files")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        commands = load_commands(args.commands)
        serial_port = open_serial(args.port, args.baud_rate, args.timeout)
        try:
            time.sleep(args.startup_delay)
            serial_port.reset_input_buffer()
            results = run_commands(serial_port, commands, args.timeout)
        finally:
            serial_port.close()
        write_results(args.output, results)
        compare_results(args.output, args.reference)
    except (EncapsTestError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("FAIL: interrupted", file=sys.stderr)
        return 130

    print(f"PASS: {len(results)} SS result(s) match {args.reference}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
