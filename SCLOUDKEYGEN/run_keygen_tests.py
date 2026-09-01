#!/usr/bin/env python3
"""Replay Scloud+ KeyGen KAT records through the board UART protocol."""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_VECTORS = (
    PROJECT_ROOT
    / "Scloud+"
    / "Test_Vectors"
    / "KAT_KEM_Scloudplus-128-SM3-packed10.txt"
)
SUPPORTED_PARAMETERS = {128, 192, 256}
KAT_NAME_PATTERN = re.compile(
    r"^KAT_KEM_Scloudplus-(?P<parameter>\d+)-(?P<family>[A-Z0-9]+)-packed10\.txt$"
)


class KeygenTestError(RuntimeError):
    """Raised when KAT input, UART data, or a board result is invalid."""


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...

    def readline(self) -> bytes: ...

    def reset_input_buffer(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class KeygenVector:
    count: int
    seed: bytes
    public_key: bytes
    secret_key: bytes


def parse_decimal(value: str, field: str, line_number: int) -> int:
    try:
        return int(value, 10)
    except ValueError as error:
        raise KeygenTestError(
            f"line {line_number}: {field} must be a decimal integer"
        ) from error


def parse_hex(value: str, field: str, line_number: int) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise KeygenTestError(
            f"line {line_number}: {field} contains invalid hex"
        ) from error


def finish_record(fields: dict[str, tuple[str, int]]) -> KeygenVector:
    required = {"Count", "Seed_Len", "Seed", "PK_Len", "PK", "SK_Len", "SK"}
    missing = sorted(required - fields.keys())
    if missing:
        raise KeygenTestError(f"KAT record is missing fields: {', '.join(missing)}")

    count = parse_decimal(fields["Count"][0], "Count", fields["Count"][1])
    seed_len = parse_decimal(
        fields["Seed_Len"][0], "Seed_Len", fields["Seed_Len"][1]
    )
    pk_len = parse_decimal(fields["PK_Len"][0], "PK_Len", fields["PK_Len"][1])
    sk_len = parse_decimal(fields["SK_Len"][0], "SK_Len", fields["SK_Len"][1])
    seed = parse_hex(fields["Seed"][0], "Seed", fields["Seed"][1])
    public_key = parse_hex(fields["PK"][0], "PK", fields["PK"][1])
    secret_key = parse_hex(fields["SK"][0], "SK", fields["SK"][1])

    if seed_len != 64 or len(seed) != seed_len:
        raise KeygenTestError(
            f"Count {count}: Seed_Len must be 64 and match Seed"
        )
    if len(public_key) != pk_len:
        raise KeygenTestError(f"Count {count}: PK_Len does not match PK")
    if len(secret_key) != sk_len:
        raise KeygenTestError(f"Count {count}: SK_Len does not match SK")
    return KeygenVector(count, seed, public_key, secret_key)


def load_vectors(path: Path) -> tuple[int, list[KeygenVector]]:
    match = KAT_NAME_PATTERN.match(path.name)
    if match is None:
        raise KeygenTestError(
            "vector filename must match "
            "KAT_KEM_Scloudplus-<parameter>-<family>-packed10.txt"
        )
    parameter = int(match.group("parameter"))
    family = match.group("family")
    if family != "SM3" or parameter not in SUPPORTED_PARAMETERS:
        raise KeygenTestError(
            "board firmware supports only Scloudplus-128/192/256-SM3 vectors"
        )

    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise KeygenTestError(f"cannot read vector file {path}: {error}") from error

    vectors: list[KeygenVector] = []
    fields: dict[str, tuple[str, int]] = {}
    wanted = {"Count", "Seed_Len", "Seed", "PK_Len", "PK", "SK_Len", "SK"}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            if fields:
                vectors.append(finish_record(fields))
                fields = {}
            continue
        name, separator, value = line.partition(" = ")
        if not separator:
            raise KeygenTestError(f"line {line_number}: expected '<field> = <value>'")
        if name in wanted:
            if name in fields:
                raise KeygenTestError(f"line {line_number}: duplicate field {name}")
            fields[name] = (value, line_number)
    if fields:
        vectors.append(finish_record(fields))
    if not vectors:
        raise KeygenTestError(f"vector file {path} contains no records")
    return parameter, vectors


def receive_result(
    serial_port: SerialPort, parameter: int, timeout: float
) -> tuple[bytes, bytes, dict[str, int]]:
    deadline = time.monotonic() + timeout
    saw_ok = False
    public_key: bytes | None = None
    secret_key: bytes | None = None
    cycles: dict[str, int] = {}

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
        if line.startswith("ERROR"):
            raise KeygenTestError(f"board returned {line}")
        if line == f"OK PARA={parameter} FAMILY=SM3":
            saw_ok = True
        elif line.startswith("PK="):
            if public_key is not None:
                raise KeygenTestError("board returned more than one PK field")
            public_key = parse_hex(line[3:], "board PK", 0)
        elif line.startswith("SK="):
            if secret_key is not None:
                raise KeygenTestError("board returned more than one SK field")
            secret_key = parse_hex(line[3:], "board SK", 0)
        elif line.startswith("CYCLES_"):
            name, separator, value = line.partition("=")
            if not separator or name in cycles:
                raise KeygenTestError(f"invalid board cycle field {line!r}")
            cycles[name] = parse_decimal(value, name, 0)
        elif line == "END":
            if not saw_ok:
                raise KeygenTestError("board response ended without the expected OK line")
            if public_key is None or secret_key is None:
                raise KeygenTestError("board response ended without PK and SK")
            return public_key, secret_key, cycles

    raise KeygenTestError(f"timed out after {timeout:g}s waiting for END")


def run_vectors(
    serial_port: SerialPort,
    parameter: int,
    vectors: Sequence[KeygenVector],
    response_timeout: float,
) -> None:
    for index, vector in enumerate(vectors, start=1):
        command = (
            f"KEYGEN {parameter} {vector.seed.hex().upper()}\n".encode("ascii")
        )
        print(f"[{index}/{len(vectors)}] Count={vector.count} TX KEYGEN <Seed>")
        written = serial_port.write(command)
        if written != len(command):
            raise KeygenTestError(
                f"UART short write: sent {written} of {len(command)} bytes"
            )
        serial_port.flush()
        public_key, secret_key, cycles = receive_result(
            serial_port, parameter, response_timeout
        )
        if public_key != vector.public_key:
            raise KeygenTestError(f"Count {vector.count}: PK mismatch")
        if secret_key != vector.secret_key:
            raise KeygenTestError(f"Count {vector.count}: SK mismatch")
        total = cycles.get("CYCLES_ALGORITHM_TOTAL")
        suffix = f", cycles={total}" if total is not None else ""
        print(f"  PASS PK={len(public_key)} bytes SK={len(secret_key)} bytes{suffix}")


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
        description="Replay Scloud+ SM3 KeyGen KAT records on the board."
    )
    parser.add_argument("--port", required=True, help="serial device, e.g. /dev/ttyUSB0")
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--baud-rate", type=int, default=115200)
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="maximum seconds per vector (default: 120)",
    )
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=1.0,
        help="seconds to wait after opening the port (default: 1)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.timeout <= 0 or args.startup_delay < 0:
            raise KeygenTestError("timeout must be positive and startup delay nonnegative")
        parameter, vectors = load_vectors(args.vectors)
        serial_port = open_serial(args.port, args.baud_rate, args.timeout)
        try:
            time.sleep(args.startup_delay)
            serial_port.reset_input_buffer()
            run_vectors(serial_port, parameter, vectors, args.timeout)
        finally:
            serial_port.close()
        print(f"PASS: all {len(vectors)} Scloud+{parameter}-SM3 KeyGen vectors matched")
        return 0
    except KeygenTestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
