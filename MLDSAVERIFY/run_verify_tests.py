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
SUPPORTED_PARAMETERS = {44: 2, 65: 3, 87: 5}
PUBLIC_KEY_BYTES = {44: 1312, 65: 1952, 87: 2592}
SIGNATURE_BYTES = {44: 2420, 65: 3309, 87: 4627}
INPUT_BYTES = 32


class VerifyTestError(RuntimeError):
    pass


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...
    def flush(self) -> None: ...
    def readline(self) -> bytes: ...
    def reset_input_buffer(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class VerifyInput:
    keygen_seed: bytes
    message: bytes
    sign_random: bytes


@dataclass(frozen=True)
class VerifyVector:
    label: str
    public_key: bytes
    message: bytes
    signature: bytes
    expected_valid: bool


def parse_hex(value: str, field: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise VerifyTestError(f"{field} contains invalid hex") from error


def load_inputs(path: Path, parameter: int) -> list[VerifyInput]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise VerifyTestError(f"cannot read command file {path}: {error}") from error

    inputs: list[VerifyInput] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 5 or fields[0] != "VERIFY":
            raise VerifyTestError(
                f"line {line_number}: expected VERIFY <parameter> "
                "<keygen-seed> <message> <sign-random>"
            )
        try:
            line_parameter = int(fields[1])
        except ValueError as error:
            raise VerifyTestError(f"line {line_number}: invalid parameter") from error
        if line_parameter != parameter:
            raise VerifyTestError(
                f"line {line_number}: command parameter {line_parameter} "
                f"does not match {parameter}"
            )
        values = [
            parse_hex(fields[index], f"line {line_number} {name}")
            for index, name in ((2, "keygen seed"), (3, "message"),
                                (4, "sign random"))
        ]
        if any(len(value) != INPUT_BYTES for value in values):
            raise VerifyTestError(
                f"line {line_number}: every input must contain {INPUT_BYTES} bytes"
            )
        inputs.append(VerifyInput(*values))
    if not inputs:
        raise VerifyTestError(f"command file {path} contains no test cases")
    return inputs


def build_golden(parameter: int, inputs: Sequence[VerifyInput]) -> list[VerifyVector]:
    mode = SUPPORTED_PARAMETERS[parameter]
    reference = PROJECT_ROOT / "e203_hbirdv2/scripts/sw/pqc/dilithium/ref"
    source_names = [
        "sign", "packing", "polyvec", "poly", "ntt", "reduce", "rounding",
        "symmetric-shake", "fips202",
    ]
    sources = [str(reference / f"{name}.c") for name in source_names]
    public_key_bytes = PUBLIC_KEY_BYTES[parameter]
    signature_bytes = SIGNATURE_BYTES[parameter]

    try:
        with tempfile.TemporaryDirectory(prefix="mldsa-verify-") as directory:
            helper = Path(directory) / "generate_golden"
            subprocess.run(
                ["cc", "-O2", "-std=c11", "-ffunction-sections",
                 f"-DDILITHIUM_MODE={mode}", "-I", str(reference),
                 str(SCRIPT_DIR / "generate_golden.c"), *sources,
                 "-Wl,--gc-sections", "-o", str(helper)],
                check=True, capture_output=True,
            )
            vectors: list[VerifyVector] = []
            for index, source in enumerate(inputs, start=1):
                output = subprocess.run(
                    [str(helper), source.keygen_seed.hex(), source.message.hex(),
                     source.sign_random.hex()],
                    check=True, capture_output=True,
                ).stdout
                expected_bytes = public_key_bytes + signature_bytes
                if len(output) != expected_bytes:
                    raise VerifyTestError(
                        f"software reference returned {len(output)} bytes, "
                        f"expected {expected_bytes}"
                    )
                public_key = output[:public_key_bytes]
                signature = output[public_key_bytes:]
                vectors.append(VerifyVector(
                    f"base-{index}-valid", public_key, source.message,
                    signature, True,
                ))
                tampered = bytes([signature[0] ^ 1]) + signature[1:]
                vectors.append(VerifyVector(
                    f"base-{index}-tampered", public_key, source.message,
                    tampered, False,
                ))
            return vectors
    except OSError as error:
        raise VerifyTestError(f"cannot run host C compiler: {error}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise VerifyTestError(f"software reference failed: {detail}") from error


def receive_result(
    serial_port: SerialPort, parameter: int, timeout: float
) -> tuple[bool, dict[str, str]]:
    deadline = time.monotonic() + timeout
    saw_ok = False
    valid: bool | None = None
    metrics: dict[str, str] = {}

    while time.monotonic() < deadline:
        raw_line = serial_port.readline()
        if not raw_line:
            continue
        try:
            line = raw_line.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise VerifyTestError("board returned non-ASCII UART data") from error
        if not line:
            continue
        if line.startswith("ERROR"):
            raise VerifyTestError(f"board returned {line}")
        if line == f"OK PARA={parameter}":
            saw_ok = True
        elif line == "VALID=1":
            valid = True
        elif line == "VALID=0":
            valid = False
        elif "=" in line:
            name, value = line.split("=", 1)
            if name.startswith(("CYCLES_", "POLY_", "SAMPLER_", "HASH_")):
                if name in metrics:
                    raise VerifyTestError(f"duplicate board metric {name}")
                metrics[name] = value
        elif line == "END":
            if not saw_ok or valid is None:
                raise VerifyTestError("incomplete board response")
            return valid, metrics
    raise VerifyTestError(f"timed out after {timeout:g}s waiting for END")


def run_vectors(
    serial_port: SerialPort,
    parameter: int,
    vectors: Sequence[VerifyVector],
    response_timeout: float,
    cpu_mhz: float | None = None,
) -> None:
    for index, vector in enumerate(vectors, start=1):
        command = (
            f"VERIFY {parameter} {vector.public_key.hex().upper()} "
            f"{vector.message.hex().upper()} {vector.signature.hex().upper()}\n"
        ).encode("ascii")
        print(f"[{index}/{len(vectors)}] TX ML-DSA-{parameter} Verify {vector.label}")
        if serial_port.write(command) != len(command):
            raise VerifyTestError("UART short write")
        serial_port.flush()
        valid, metrics = receive_result(serial_port, parameter, response_timeout)
        if valid != vector.expected_valid:
            raise VerifyTestError(
                f"case {index} ({vector.label}): board returned "
                f"VALID={int(valid)}, expected {int(vector.expected_valid)}"
            )
        cycles = metrics.get("CYCLES_ALGORITHM_TOTAL")
        timing = ""
        if cycles is not None:
            timing = f", cycles={cycles}"
            if cpu_mhz is not None:
                timing += f", {int(cycles) / (cpu_mhz * 1000):.6f} ms"
        print(f"  PASS VALID={int(valid)}{timing}")
        for name in ("POLY_OPERATIONS", "POLY_HW_CYCLES", "SAMPLER_CALLS",
                     "SAMPLER_HW_CYCLES", "HASH_JOBS"):
            if name in metrics:
                print(f"  {name}={metrics[name]}")


def open_serial(port: str, baud_rate: int, response_timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise VerifyTestError(
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
        raise VerifyTestError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run project KD ML-DSA Verify vectors over UART."
    )
    parser.add_argument(
        "--parameter", type=int, choices=sorted(SUPPORTED_PARAMETERS), default=44
    )
    parser.add_argument("--port", help="serial device, e.g. /dev/ttyUSB2")
    parser.add_argument("--commands", type=Path)
    parser.add_argument("--baud-rate", type=int, default=115200)
    parser.add_argument("--cpu-mhz", type=float)
    parser.add_argument("--timeout", type=float, default=300.0)
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
            raise VerifyTestError("timeout must be positive and startup delay nonnegative")
        if args.cpu_mhz is not None and (
            not math.isfinite(args.cpu_mhz) or args.cpu_mhz <= 0
        ):
            raise VerifyTestError("cpu-mhz must be finite and positive")
        command_path = (
            args.commands or SCRIPT_DIR / f"verify_commands_{args.parameter}.txt"
        )
        inputs = load_inputs(command_path, args.parameter)
        vectors = build_golden(args.parameter, inputs)
        print(f"Built {len(vectors)} software-reference golden case(s)")
        if args.golden_only:
            return 0
        if args.port is None:
            raise VerifyTestError("specify --port, or use --golden-only")
        serial_port = open_serial(args.port, args.baud_rate, args.timeout)
        try:
            time.sleep(args.startup_delay)
            serial_port.reset_input_buffer()
            run_vectors(serial_port, args.parameter, vectors, args.timeout, args.cpu_mhz)
        finally:
            serial_port.close()
        print(f"PASS: all ML-DSA-{args.parameter} Verify cases matched")
        return 0
    except VerifyTestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
