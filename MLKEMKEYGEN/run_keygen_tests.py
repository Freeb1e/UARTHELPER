#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
SUPPORTED_PARAMETERS = {512: 2, 768: 3, 1024: 4}
KEY_SIZES = {
    512: (800, 1632),
    768: (1184, 2400),
    1024: (1568, 3168),
}


class KeygenTestError(RuntimeError):
    pass


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...
    def flush(self) -> None: ...
    def readline(self) -> bytes: ...
    def reset_input_buffer(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class KeygenVector:
    coins: bytes
    public_key: bytes
    secret_key: bytes


def parse_hex(value: str, field: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise KeygenTestError(f"{field} contains invalid hex") from error


def load_coins(path: Path, parameter: int) -> list[bytes]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise KeygenTestError(f"cannot read command file {path}: {error}") from error

    coins_list: list[bytes] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[0] != "KEYGEN":
            raise KeygenTestError(f"line {line_number}: expected KEYGEN <parameter> <coins>")
        try:
            line_parameter = int(fields[1])
        except ValueError as error:
            raise KeygenTestError(f"line {line_number}: invalid parameter") from error
        if line_parameter != parameter:
            raise KeygenTestError(
                f"line {line_number}: command parameter {line_parameter} does not match {parameter}"
            )
        coins = parse_hex(fields[2], f"line {line_number} coins")
        if len(coins) != 64:
            raise KeygenTestError(f"line {line_number}: coins must contain 64 bytes")
        coins_list.append(coins)
    if not coins_list:
        raise KeygenTestError(f"command file {path} contains no test cases")
    return coins_list


def build_golden(parameter: int, coins_list: Sequence[bytes]) -> list[KeygenVector]:
    kyber_k = SUPPORTED_PARAMETERS[parameter]
    reference = PROJECT_ROOT / "e203_hbirdv2/scripts/sw/pqc/kyber/ref"
    source_names = [
        "kem", "indcpa", "poly", "polyvec", "ntt", "reduce", "cbd",
        "verify", "symmetric-shake", "fips202",
    ]
    sources = [str(reference / f"{name}.c") for name in source_names]
    public_key_bytes, secret_key_bytes = KEY_SIZES[parameter]
    expected_bytes = public_key_bytes + secret_key_bytes

    try:
        with tempfile.TemporaryDirectory(prefix="mlkem-keygen-") as directory:
            helper = Path(directory) / "generate_golden"
            subprocess.run(
                ["cc", "-O2", "-std=c11", "-ffunction-sections",
                 f"-DKYBER_K={kyber_k}", "-I", str(reference),
                 str(SCRIPT_DIR / "generate_golden.c"), *sources,
                 "-Wl,--gc-sections", "-o", str(helper)],
                check=True, capture_output=True,
            )
            vectors = []
            for coins in coins_list:
                output = subprocess.run(
                    [str(helper), coins.hex()], check=True, capture_output=True,
                ).stdout
                if len(output) != expected_bytes:
                    raise KeygenTestError(
                        f"software reference returned {len(output)} bytes, expected {expected_bytes}"
                    )
                vectors.append(KeygenVector(
                    coins,
                    output[:public_key_bytes],
                    output[public_key_bytes:],
                ))
            return vectors
    except OSError as error:
        raise KeygenTestError(f"cannot run host C compiler: {error}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise KeygenTestError(f"software reference failed: {detail}") from error


def receive_result(
    serial_port: SerialPort, parameter: int, timeout: float
) -> tuple[bytes, bytes, dict[str, str]]:
    deadline = time.monotonic() + timeout
    saw_ok = False
    public_key: bytes | None = None
    secret_key: bytes | None = None
    metrics: dict[str, str] = {}

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
        if line == f"OK PARA={parameter}":
            saw_ok = True
        elif line.startswith("PK="):
            public_key = parse_hex(line[3:], "board PK")
        elif line.startswith("SK="):
            secret_key = parse_hex(line[3:], "board SK")
        elif "=" in line:
            name, value = line.split("=", 1)
            if name.startswith(("CYCLES_", "POLY_", "SAMPLER_", "HASH_")):
                if name in metrics:
                    raise KeygenTestError(f"duplicate board metric {name}")
                metrics[name] = value
        elif line == "END":
            if not saw_ok or public_key is None or secret_key is None:
                raise KeygenTestError("incomplete board response")
            return public_key, secret_key, metrics
    raise KeygenTestError(f"timed out after {timeout:g}s waiting for END")


def run_vectors(
    serial_port: SerialPort,
    parameter: int,
    vectors: Sequence[KeygenVector],
    response_timeout: float,
    cpu_mhz: float | None = None,
) -> None:
    for index, vector in enumerate(vectors, start=1):
        command = f"KEYGEN {parameter} {vector.coins.hex().upper()}\n".encode("ascii")
        print(f"[{index}/{len(vectors)}] TX ML-KEM-{parameter} KeyGen")
        if serial_port.write(command) != len(command):
            raise KeygenTestError("UART short write")
        serial_port.flush()
        public_key, secret_key, metrics = receive_result(
            serial_port, parameter, response_timeout
        )
        if public_key != vector.public_key:
            raise KeygenTestError(f"case {index}: PK mismatch")
        if secret_key != vector.secret_key:
            raise KeygenTestError(f"case {index}: SK mismatch")
        cycles = metrics.get("CYCLES_ALGORITHM_TOTAL")
        timing = ""
        if cycles is not None:
            timing = f", cycles={cycles}"
            if cpu_mhz is not None:
                timing += f", {int(cycles) / (cpu_mhz * 1000):.6f} ms"
        print(
            f"  PASS PK={len(public_key)} bytes SK={len(secret_key)} bytes{timing}"
        )
        for name in ("POLY_OPERATIONS", "POLY_HW_CYCLES", "SAMPLER_CALLS",
                     "SAMPLER_HW_CYCLES", "HASH_JOBS"):
            if name in metrics:
                print(f"  {name}={metrics[name]}")


def open_serial(port: str, baud_rate: int, response_timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise KeygenTestError(
            f"pyserial is not installed; run {sys.executable} -m pip install -r "
            f"{SCRIPT_DIR / 'requirements.txt'}"
        ) from error
    try:
        return serial.Serial(
            port=port, baudrate=baud_rate, bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
            timeout=min(0.2, response_timeout), write_timeout=response_timeout,
        )
    except serial.SerialException as error:
        raise KeygenTestError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run project KD ML-KEM KeyGen vectors over UART."
    )
    parser.add_argument("--parameter", type=int, choices=sorted(SUPPORTED_PARAMETERS), default=512)
    parser.add_argument("--port", help="serial device, e.g. /dev/ttyUSB2")
    parser.add_argument("--commands", type=Path)
    parser.add_argument("--baud-rate", type=int, default=115200)
    parser.add_argument("--cpu-mhz", type=float)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--startup-delay", type=float, default=1.0)
    parser.add_argument(
        "--golden-only", action="store_true",
        help="build host golden outputs and stop before opening UART",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.timeout <= 0 or args.startup_delay < 0:
            raise KeygenTestError("timeout must be positive and startup delay nonnegative")
        if args.cpu_mhz is not None and (
            not math.isfinite(args.cpu_mhz) or args.cpu_mhz <= 0
        ):
            raise KeygenTestError("cpu-mhz must be finite and positive")
        command_path = args.commands or SCRIPT_DIR / f"keygen_commands_{args.parameter}.txt"
        coins_list = load_coins(command_path, args.parameter)
        vectors = build_golden(args.parameter, coins_list)
        print(f"Built {len(vectors)} software-reference golden case(s)")
        if args.golden_only:
            return 0
        if args.port is None:
            raise KeygenTestError("specify --port, or use --golden-only")
        serial_port = open_serial(args.port, args.baud_rate, args.timeout)
        try:
            time.sleep(args.startup_delay)
            serial_port.reset_input_buffer()
            run_vectors(serial_port, args.parameter, vectors, args.timeout, args.cpu_mhz)
        finally:
            serial_port.close()
        print(f"PASS: all ML-KEM-{args.parameter} KeyGen cases matched")
        return 0
    except KeygenTestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

