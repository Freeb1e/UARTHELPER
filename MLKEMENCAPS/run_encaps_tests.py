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
OBJECT_SIZES = {
    512: (800, 768, 32),
    768: (1184, 1088, 32),
    1024: (1568, 1568, 32),
}


class EncapsTestError(RuntimeError):
    pass


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...
    def flush(self) -> None: ...
    def readline(self) -> bytes: ...
    def reset_input_buffer(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class EncapsInput:
    keygen_coins: bytes
    encaps_coins: bytes


@dataclass(frozen=True)
class EncapsVector:
    encaps_coins: bytes
    public_key: bytes
    ciphertext: bytes
    shared_secret: bytes


def parse_hex(value: str, field: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise EncapsTestError(f"{field} contains invalid hex") from error


def load_inputs(path: Path, parameter: int) -> list[EncapsInput]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise EncapsTestError(f"cannot read input file {path}: {error}") from error

    inputs: list[EncapsInput] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 4 or fields[0] != "ENCAPS_INPUT":
            raise EncapsTestError(
                f"line {line_number}: expected ENCAPS_INPUT <parameter> "
                "<keygen-coins> <encaps-coins>"
            )
        try:
            line_parameter = int(fields[1])
        except ValueError as error:
            raise EncapsTestError(f"line {line_number}: invalid parameter") from error
        if line_parameter != parameter:
            raise EncapsTestError(
                f"line {line_number}: input parameter {line_parameter} does not match {parameter}"
            )
        keygen_coins = parse_hex(fields[2], f"line {line_number} keygen coins")
        encaps_coins = parse_hex(fields[3], f"line {line_number} encaps coins")
        if len(keygen_coins) != 64:
            raise EncapsTestError(f"line {line_number}: keygen coins must contain 64 bytes")
        if len(encaps_coins) != 32:
            raise EncapsTestError(f"line {line_number}: encaps coins must contain 32 bytes")
        inputs.append(EncapsInput(keygen_coins, encaps_coins))
    if not inputs:
        raise EncapsTestError(f"input file {path} contains no test cases")
    return inputs


def build_golden(parameter: int, inputs: Sequence[EncapsInput]) -> list[EncapsVector]:
    kyber_k = SUPPORTED_PARAMETERS[parameter]
    reference = PROJECT_ROOT / "e203_hbirdv2/scripts/sw/pqc/kyber/ref"
    source_names = [
        "kem", "indcpa", "poly", "polyvec", "ntt", "reduce", "cbd",
        "verify", "symmetric-shake", "fips202",
    ]
    sources = [str(reference / f"{name}.c") for name in source_names]
    public_key_bytes, ciphertext_bytes, shared_secret_bytes = OBJECT_SIZES[parameter]
    expected_bytes = public_key_bytes + ciphertext_bytes + shared_secret_bytes

    try:
        with tempfile.TemporaryDirectory(prefix="mlkem-encaps-") as directory:
            helper = Path(directory) / "generate_golden"
            subprocess.run(
                ["cc", "-O2", "-std=c11", "-ffunction-sections",
                 f"-DKYBER_K={kyber_k}", "-I", str(reference),
                 str(SCRIPT_DIR / "generate_golden.c"), *sources,
                 "-Wl,--gc-sections", "-o", str(helper)],
                check=True, capture_output=True,
            )
            vectors = []
            for test_input in inputs:
                output = subprocess.run(
                    [str(helper), test_input.keygen_coins.hex(),
                     test_input.encaps_coins.hex()],
                    check=True, capture_output=True,
                ).stdout
                if len(output) != expected_bytes:
                    raise EncapsTestError(
                        f"software reference returned {len(output)} bytes, expected {expected_bytes}"
                    )
                ct_start = public_key_bytes
                ss_start = ct_start + ciphertext_bytes
                vectors.append(EncapsVector(
                    test_input.encaps_coins,
                    output[:ct_start],
                    output[ct_start:ss_start],
                    output[ss_start:],
                ))
            return vectors
    except OSError as error:
        raise EncapsTestError(f"cannot run host C compiler: {error}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise EncapsTestError(f"software reference failed: {detail}") from error


def receive_result(
    serial_port: SerialPort, parameter: int, timeout: float
) -> tuple[bytes, bytes, dict[str, str]]:
    deadline = time.monotonic() + timeout
    saw_ok = False
    ciphertext: bytes | None = None
    shared_secret: bytes | None = None
    metrics: dict[str, str] = {}

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
        if line.startswith("ERROR"):
            raise EncapsTestError(f"board returned {line}")
        if line == f"OK PARA={parameter}":
            saw_ok = True
        elif line.startswith("CT="):
            ciphertext = parse_hex(line[3:], "board CT")
        elif line.startswith("SS="):
            shared_secret = parse_hex(line[3:], "board SS")
        elif "=" in line:
            name, value = line.split("=", 1)
            if name.startswith(("CYCLES_", "POLY_", "SAMPLER_", "HASH_")):
                if name in metrics:
                    raise EncapsTestError(f"duplicate board metric {name}")
                metrics[name] = value
        elif line == "END":
            if not saw_ok or ciphertext is None or shared_secret is None:
                raise EncapsTestError("incomplete board response")
            return ciphertext, shared_secret, metrics
    raise EncapsTestError(f"timed out after {timeout:g}s waiting for END")


def run_vectors(
    serial_port: SerialPort,
    parameter: int,
    vectors: Sequence[EncapsVector],
    response_timeout: float,
    cpu_mhz: float | None = None,
) -> None:
    for index, vector in enumerate(vectors, start=1):
        command = (
            f"ENCAPS {parameter} {vector.public_key.hex().upper()} "
            f"{vector.encaps_coins.hex().upper()}\n"
        ).encode("ascii")
        print(f"[{index}/{len(vectors)}] TX ML-KEM-{parameter} Encaps")
        if serial_port.write(command) != len(command):
            raise EncapsTestError("UART short write")
        serial_port.flush()
        ciphertext, shared_secret, metrics = receive_result(
            serial_port, parameter, response_timeout
        )
        if ciphertext != vector.ciphertext:
            raise EncapsTestError(f"case {index}: CT mismatch")
        if shared_secret != vector.shared_secret:
            raise EncapsTestError(f"case {index}: SS mismatch")
        cycles = metrics.get("CYCLES_ALGORITHM_TOTAL")
        timing = ""
        if cycles is not None:
            timing = f", cycles={cycles}"
            if cpu_mhz is not None:
                timing += f", {int(cycles) / (cpu_mhz * 1000):.6f} ms"
        print(f"  PASS CT={len(ciphertext)} bytes SS={len(shared_secret)} bytes{timing}")
        for name in ("POLY_OPERATIONS", "POLY_HW_CYCLES", "SAMPLER_CALLS",
                     "SAMPLER_HW_CYCLES", "HASH_JOBS"):
            if name in metrics:
                print(f"  {name}={metrics[name]}")


def open_serial(port: str, baud_rate: int, response_timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise EncapsTestError(
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
        raise EncapsTestError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run project KD ML-KEM Encaps vectors over UART."
    )
    parser.add_argument("--parameter", type=int, choices=sorted(SUPPORTED_PARAMETERS), default=512)
    parser.add_argument("--port", help="serial device, e.g. /dev/ttyUSB2")
    parser.add_argument("--inputs", type=Path)
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
            raise EncapsTestError("timeout must be positive and startup delay nonnegative")
        if args.cpu_mhz is not None and (
            not math.isfinite(args.cpu_mhz) or args.cpu_mhz <= 0
        ):
            raise EncapsTestError("cpu-mhz must be finite and positive")
        input_path = args.inputs or SCRIPT_DIR / f"encaps_inputs_{args.parameter}.txt"
        inputs = load_inputs(input_path, args.parameter)
        vectors = build_golden(args.parameter, inputs)
        print(f"Built {len(vectors)} software-reference golden case(s)")
        if args.golden_only:
            return 0
        if args.port is None:
            raise EncapsTestError("specify --port, or use --golden-only")
        serial_port = open_serial(args.port, args.baud_rate, args.timeout)
        try:
            time.sleep(args.startup_delay)
            serial_port.reset_input_buffer()
            run_vectors(serial_port, args.parameter, vectors, args.timeout, args.cpu_mhz)
        finally:
            serial_port.close()
        print(f"PASS: all ML-KEM-{args.parameter} Encaps cases matched")
        return 0
    except EncapsTestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
