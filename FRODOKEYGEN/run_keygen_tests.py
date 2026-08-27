#!/usr/bin/env python3
"""Run Frodo KeyGen test vectors through the board UART protocol."""

from __future__ import annotations

import argparse
import difflib
import sys
import time
from pathlib import Path
from typing import Protocol, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
SECURITY_HEX_LENGTHS = {"640": 32, "976": 48, "1344": 64}
TRNG_HEX_LENGTHS = {"640": 128, "976": 176, "1344": 224}


class KeygenTestError(RuntimeError):
    """Raised when input, UART communication, or a board response is invalid."""


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...

    def readline(self) -> bytes: ...

    def reset_input_buffer(self) -> None: ...


def parse_command(line: str, line_number: int) -> tuple[str, int]:
    fields = line.split()
    if len(fields) != 5 or fields[0] != "KEYGEN":
        raise KeygenTestError(
            f"commands line {line_number}: expected "
            "KEYGEN <parameter> <cycles> <print_pk> <trng_hex>"
        )

    parameter, cycles, print_pk, trng_hex = fields[1:]
    if parameter not in TRNG_HEX_LENGTHS:
        raise KeygenTestError(
            f"commands line {line_number}: unsupported parameter {parameter!r}"
        )
    if cycles not in {"0", "1"}:
        raise KeygenTestError(
            f"commands line {line_number}: cycles must be 0 or 1"
        )
    if print_pk not in {"0", "1"}:
        raise KeygenTestError(
            f"commands line {line_number}: print_pk must be 0 or 1"
        )
    expected_length = TRNG_HEX_LENGTHS[parameter]
    if len(trng_hex) != expected_length:
        raise KeygenTestError(
            f"commands line {line_number}: Frodo-{parameter} TRNG must contain "
            f"{expected_length} hex characters, got {len(trng_hex)}"
        )
    try:
        bytes.fromhex(trng_hex)
    except ValueError as error:
        raise KeygenTestError(
            f"commands line {line_number}: TRNG contains non-hex characters"
        ) from error

    return " ".join(fields), int(parameter)


def load_commands(path: Path) -> list[tuple[str, int]]:
    commands: list[tuple[str, int]] = []
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise KeygenTestError(f"cannot read commands file {path}: {error}") from error

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        commands.append(parse_command(line, line_number))

    if not commands:
        raise KeygenTestError(f"commands file {path} contains no test cases")
    return commands


def receive_pkh(
    serial_port: SerialPort, command: str, parameter: int, timeout: float
) -> str:
    deadline = time.monotonic() + timeout
    saw_ok = False
    pkh: str | None = None

    while time.monotonic() < deadline:
        raw_line = serial_port.readline()
        if not raw_line:
            continue
        try:
            line = raw_line.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise KeygenTestError("board returned non-ASCII UART data") from error
        if not line:
            continue

        print(f"  RX {line}")
        if line.startswith("ERROR"):
            raise KeygenTestError(f"board rejected {command!r}: {line}")
        if line == f"OK PARA={parameter}":
            saw_ok = True
        elif line.startswith("PKH="):
            if pkh is not None:
                raise KeygenTestError("board returned more than one PKH line")
            pkh = line.removeprefix("PKH=").upper()
        elif line == "END":
            if not saw_ok:
                raise KeygenTestError("board response ended without the expected OK line")
            if pkh is None:
                raise KeygenTestError("board response ended without a PKH line")
            expected_length = SECURITY_HEX_LENGTHS[str(parameter)]
            if len(pkh) != expected_length:
                raise KeygenTestError(
                    f"Frodo-{parameter} PKH must contain {expected_length} hex "
                    f"characters, got {len(pkh)}"
                )
            try:
                bytes.fromhex(pkh)
            except ValueError as error:
                raise KeygenTestError("board PKH contains non-hex characters") from error
            return pkh

    raise KeygenTestError(f"timed out after {timeout:g}s waiting for END")


def run_commands(
    serial_port: SerialPort,
    commands: Sequence[tuple[str, int]],
    response_timeout: float,
) -> list[str]:
    results: list[str] = []
    total = len(commands)

    for index, (command, parameter) in enumerate(commands, start=1):
        print(f"[{index}/{total}] TX {command}")
        payload = f"{command}\n".encode("ascii")
        written = serial_port.write(payload)
        if written != len(payload):
            raise KeygenTestError(
                f"UART short write: sent {written} of {len(payload)} bytes"
            )
        serial_port.flush()
        results.append(receive_pkh(serial_port, command, parameter, response_timeout))

    return results


def write_results(path: Path, results: Sequence[str]) -> None:
    content = "".join(f"{pkh}\n" for pkh in results)
    try:
        path.write_text(content, encoding="ascii", newline="\n")
    except OSError as error:
        raise KeygenTestError(f"cannot write result file {path}: {error}") from error


def compare_results(result_path: Path, reference_path: Path) -> None:
    try:
        actual_bytes = result_path.read_bytes()
        expected_bytes = reference_path.read_bytes()
    except OSError as error:
        raise KeygenTestError(f"cannot compare result files: {error}") from error
    if actual_bytes == expected_bytes:
        return

    try:
        expected = reference_path.read_text(encoding="ascii").splitlines(keepends=True)
        actual = result_path.read_text(encoding="ascii").splitlines(keepends=True)
    except (OSError, UnicodeError) as error:
        raise KeygenTestError(f"cannot show result difference: {error}") from error
    difference = "".join(
        difflib.unified_diff(
            expected,
            actual,
            fromfile=str(reference_path),
            tofile=str(result_path),
        )
    )
    raise KeygenTestError(f"PKH comparison failed:\n{difference.rstrip()}")


def open_serial(port: str, baud_rate: int, response_timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise KeygenTestError(
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
        raise KeygenTestError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send Frodo KeyGen commands sequentially and compare PKH results."
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
        default=SCRIPT_DIR / "keygen_commands.txt",
    )
    parser.add_argument(
        "--reference",
        type=Path,
        default=SCRIPT_DIR / "pkh_ref.txt",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=SCRIPT_DIR / "pkh.txt",
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
    except (KeygenTestError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("FAIL: interrupted", file=sys.stderr)
        return 130

    print(f"PASS: {len(results)} PKH result(s) match {args.reference}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
