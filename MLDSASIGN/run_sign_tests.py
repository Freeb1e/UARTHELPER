#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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
SECRET_KEY_BYTES = {44: 2560, 65: 4032, 87: 4896}
SIGNATURE_BYTES = {44: 2420, 65: 3309, 87: 4627}
INPUT_BYTES = 32
THEORETICAL_ATTEMPTS = {44: 4.25, 65: 5.10, 87: 3.85}


class SignTestError(RuntimeError):
    pass


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...
    def flush(self) -> None: ...
    def readline(self) -> bytes: ...
    def reset_input_buffer(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class SignInput:
    keygen_seed: bytes
    message: bytes
    sign_random: bytes


@dataclass(frozen=True)
class SignVector:
    source: SignInput
    secret_key: bytes
    signature: bytes


@dataclass(frozen=True)
class SignMeasurement:
    algorithm_cycles: int
    attempts: int
    attempt_cycles: int
    success_cycles: int
    reject_z: int
    reject_z_cycles: int
    reject_w0: int
    reject_w0_cycles: int
    reject_h: int
    reject_h_cycles: int
    reject_omega: int
    reject_omega_cycles: int

    @property
    def rejects(self) -> int:
        return self.reject_z + self.reject_w0 + self.reject_h + self.reject_omega

    @property
    def reject_cycles(self) -> int:
        return (
            self.reject_z_cycles + self.reject_w0_cycles +
            self.reject_h_cycles + self.reject_omega_cycles
        )

    @property
    def fixed_cycles(self) -> int:
        return self.algorithm_cycles - self.attempt_cycles


def parse_hex(value: str, field: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise SignTestError(f"{field} contains invalid hex") from error


def load_inputs(path: Path, parameter: int) -> list[SignInput]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise SignTestError(f"cannot read command file {path}: {error}") from error

    inputs: list[SignInput] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 5 or fields[0] != "SIGN":
            raise SignTestError(
                f"line {line_number}: expected SIGN <parameter> "
                "<keygen-seed> <message> <sign-random>"
            )
        try:
            line_parameter = int(fields[1])
        except ValueError as error:
            raise SignTestError(f"line {line_number}: invalid parameter") from error
        if line_parameter != parameter:
            raise SignTestError(
                f"line {line_number}: command parameter {line_parameter} "
                f"does not match {parameter}"
            )
        values = [
            parse_hex(fields[index], f"line {line_number} {name}")
            for index, name in ((2, "keygen seed"), (3, "message"),
                                (4, "sign random"))
        ]
        if any(len(value) != INPUT_BYTES for value in values):
            raise SignTestError(
                f"line {line_number}: every input must contain {INPUT_BYTES} bytes"
            )
        inputs.append(SignInput(*values))
    if not inputs:
        raise SignTestError(f"command file {path} contains no test cases")
    return inputs


def generate_benchmark_inputs(
    parameter: int, count: int, start: int = 0
) -> list[SignInput]:
    if count <= 0 or start < 0:
        raise SignTestError("benchmark count must be positive and start nonnegative")

    def derive(case: int, field: str) -> bytes:
        domain = f"MLDSA-{parameter}-SIGN-{case}-{field}".encode("ascii")
        return hashlib.shake_256(domain).digest(INPUT_BYTES)

    return [
        SignInput(
            derive(case, "KEYGEN"),
            derive(case, "MESSAGE"),
            derive(case, "RANDOM"),
        )
        for case in range(start, start + count)
    ]


def build_golden(parameter: int, inputs: Sequence[SignInput]) -> list[SignVector]:
    mode = SUPPORTED_PARAMETERS[parameter]
    reference = PROJECT_ROOT / "e203_hbirdv2/scripts/sw/pqc/dilithium/ref"
    source_names = [
        "sign", "packing", "polyvec", "poly", "ntt", "reduce", "rounding",
        "symmetric-shake", "fips202",
    ]
    sources = [str(reference / f"{name}.c") for name in source_names]
    secret_key_bytes = SECRET_KEY_BYTES[parameter]
    signature_bytes = SIGNATURE_BYTES[parameter]

    try:
        with tempfile.TemporaryDirectory(prefix="mldsa-sign-") as directory:
            helper = Path(directory) / "generate_golden"
            subprocess.run(
                ["cc", "-O2", "-std=c11", "-ffunction-sections",
                 f"-DDILITHIUM_MODE={mode}", "-I", str(reference),
                 str(SCRIPT_DIR / "generate_golden.c"), *sources,
                 "-Wl,--gc-sections", "-o", str(helper)],
                check=True, capture_output=True,
            )
            vectors = []
            for source in inputs:
                output = subprocess.run(
                    [str(helper), source.keygen_seed.hex(), source.message.hex(),
                     source.sign_random.hex()],
                    check=True, capture_output=True,
                ).stdout
                expected_bytes = secret_key_bytes + signature_bytes
                if len(output) != expected_bytes:
                    raise SignTestError(
                        f"software reference returned {len(output)} bytes, "
                        f"expected {expected_bytes}"
                    )
                vectors.append(SignVector(
                    source=source,
                    secret_key=output[:secret_key_bytes],
                    signature=output[secret_key_bytes:],
                ))
            return vectors
    except OSError as error:
        raise SignTestError(f"cannot run host C compiler: {error}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise SignTestError(f"software reference failed: {detail}") from error


def receive_result(
    serial_port: SerialPort, parameter: int, timeout: float
) -> tuple[bytes, dict[str, str]]:
    deadline = time.monotonic() + timeout
    saw_ok = False
    signature: bytes | None = None
    metrics: dict[str, str] = {}

    while time.monotonic() < deadline:
        raw_line = serial_port.readline()
        if not raw_line:
            continue
        try:
            line = raw_line.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise SignTestError("board returned non-ASCII UART data") from error
        if not line:
            continue
        if line.startswith("ERROR"):
            raise SignTestError(f"board returned {line}")
        if line == f"OK PARA={parameter}":
            saw_ok = True
        elif line.startswith("SIG="):
            signature = parse_hex(line[4:], "board signature")
        elif "=" in line:
            name, value = line.split("=", 1)
            if name.startswith(
                ("CYCLES_", "POLY_", "SAMPLER_", "HASH_", "SIGN_")
            ):
                if name in metrics:
                    raise SignTestError(f"duplicate board metric {name}")
                metrics[name] = value
        elif line == "END":
            if not saw_ok or signature is None:
                raise SignTestError("incomplete board response")
            return signature, metrics
    raise SignTestError(f"timed out after {timeout:g}s waiting for END")


def parse_measurement(metrics: dict[str, str]) -> SignMeasurement:
    names = {
        "algorithm_cycles": "CYCLES_ALGORITHM_TOTAL",
        "attempts": "SIGN_ATTEMPTS",
        "attempt_cycles": "SIGN_ATTEMPT_CYCLES",
        "success_cycles": "SIGN_SUCCESS_CYCLES",
        "reject_z": "SIGN_REJECT_Z",
        "reject_z_cycles": "SIGN_REJECT_Z_CYCLES",
        "reject_w0": "SIGN_REJECT_W0",
        "reject_w0_cycles": "SIGN_REJECT_W0_CYCLES",
        "reject_h": "SIGN_REJECT_H",
        "reject_h_cycles": "SIGN_REJECT_H_CYCLES",
        "reject_omega": "SIGN_REJECT_OMEGA",
        "reject_omega_cycles": "SIGN_REJECT_OMEGA_CYCLES",
    }
    values: dict[str, int] = {}
    for field, name in names.items():
        if name not in metrics:
            raise SignTestError(
                f"board response is missing {name}; reload the current Sign firmware"
            )
        try:
            values[field] = int(metrics[name])
        except ValueError as error:
            raise SignTestError(f"board returned invalid integer for {name}") from error
    measurement = SignMeasurement(**values)
    if measurement.attempts < 1 or measurement.rejects != measurement.attempts - 1:
        raise SignTestError("board returned inconsistent Sign attempt counters")
    if (
        measurement.attempt_cycles !=
        measurement.success_cycles + measurement.reject_cycles
    ):
        raise SignTestError("board returned inconsistent Sign attempt cycle totals")
    if measurement.attempt_cycles > measurement.algorithm_cycles:
        raise SignTestError("board attempt cycles exceed total algorithm cycles")
    return measurement


def print_profile_summary(
    parameter: int, measurements: Sequence[SignMeasurement]
) -> None:
    cases = len(measurements)
    total_attempts = sum(item.attempts for item in measurements)
    total_rejects = sum(item.rejects for item in measurements)
    total_reject_cycles = sum(item.reject_cycles for item in measurements)
    mean_total = sum(item.algorithm_cycles for item in measurements) / cases
    mean_fixed = sum(item.fixed_cycles for item in measurements) / cases
    mean_success = sum(item.success_cycles for item in measurements) / cases
    theoretical_attempts = THEORETICAL_ATTEMPTS[parameter]

    print(f"PROFILE ML-DSA-{parameter} Sign ({cases} case(s))")
    print(f"  MEASURED_MEAN_ATTEMPTS={total_attempts / cases:.6f}")
    print(f"  MEASURED_MEAN_TOTAL_CYCLES={mean_total:.3f}")
    print(f"  MEASURED_MEAN_FIXED_CYCLES={mean_fixed:.3f}")
    print(f"  MEASURED_MEAN_SUCCESS_ATTEMPT_CYCLES={mean_success:.3f}")
    if total_rejects == 0:
        print("  THEORETICAL_MEAN_TOTAL_CYCLES=unavailable (no rejected attempts)")
        return
    mean_reject = total_reject_cycles / total_rejects
    theoretical_cycles = (
        mean_fixed + (theoretical_attempts - 1.0) * mean_reject + mean_success
    )
    print(f"  MEASURED_MEAN_REJECTED_ATTEMPT_CYCLES={mean_reject:.3f}")
    for label, count_field, cycle_field in (
        ("Z", "reject_z", "reject_z_cycles"),
        ("W0", "reject_w0", "reject_w0_cycles"),
        ("H", "reject_h", "reject_h_cycles"),
        ("OMEGA", "reject_omega", "reject_omega_cycles"),
    ):
        count = sum(getattr(item, count_field) for item in measurements)
        if count != 0:
            cycles = sum(getattr(item, cycle_field) for item in measurements)
            print(f"  MEASURED_REJECT_{label}_MEAN_CYCLES={cycles / count:.3f}")
    print(f"  THEORETICAL_MEAN_ATTEMPTS={theoretical_attempts:.2f}")
    print(f"  THEORETICAL_MEAN_TOTAL_CYCLES={theoretical_cycles:.3f}")


def run_vectors(
    serial_port: SerialPort,
    parameter: int,
    vectors: Sequence[SignVector],
    response_timeout: float,
    cpu_mhz: float | None = None,
) -> list[SignMeasurement]:
    measurements: list[SignMeasurement] = []
    for index, vector in enumerate(vectors, start=1):
        source = vector.source
        command = (
            f"SIGN {parameter} {vector.secret_key.hex().upper()} "
            f"{source.message.hex().upper()} {source.sign_random.hex().upper()}\n"
        ).encode("ascii")
        print(f"[{index}/{len(vectors)}] TX ML-DSA-{parameter} Sign")
        if serial_port.write(command) != len(command):
            raise SignTestError("UART short write")
        serial_port.flush()
        signature, metrics = receive_result(serial_port, parameter, response_timeout)
        if len(signature) != SIGNATURE_BYTES[parameter]:
            raise SignTestError(
                f"case {index}: signature has {len(signature)} bytes, "
                f"expected {SIGNATURE_BYTES[parameter]}"
            )
        if signature != vector.signature:
            mismatch = next(
                offset for offset, (actual, expected) in
                enumerate(zip(signature, vector.signature))
                if actual != expected
            )
            raise SignTestError(
                f"case {index}: signature mismatch at byte {mismatch}: "
                f"board={signature[mismatch]:02x} "
                f"reference={vector.signature[mismatch]:02x}"
            )
        measurement = parse_measurement(metrics)
        measurements.append(measurement)
        cycles = metrics.get("CYCLES_ALGORITHM_TOTAL")
        timing = ""
        if cycles is not None:
            timing = f", cycles={cycles}"
            if cpu_mhz is not None:
                timing += f", {int(cycles) / (cpu_mhz * 1000):.6f} ms"
        print(f"  PASS SIG={len(signature)} bytes{timing}")
        print(
            f"  SIGN_ATTEMPTS={measurement.attempts} "
            f"REJECTS={measurement.rejects} "
            f"FIXED_CYCLES={measurement.fixed_cycles}"
        )
        print(
            f"  ATTEMPT_CYCLES={measurement.attempt_cycles} "
            f"SUCCESS_ATTEMPT_CYCLES={measurement.success_cycles}"
        )
        print(
            f"  REJECT_Z={measurement.reject_z} "
            f"REJECT_W0={measurement.reject_w0} "
            f"REJECT_H={measurement.reject_h} "
            f"REJECT_OMEGA={measurement.reject_omega}"
        )
        for name in ("POLY_OPERATIONS", "POLY_HW_CYCLES", "SAMPLER_CALLS",
                     "SAMPLER_HW_CYCLES", "HASH_JOBS"):
            if name in metrics:
                print(f"  {name}={metrics[name]}")
    print_profile_summary(parameter, measurements)
    return measurements


def open_serial(port: str, baud_rate: int, response_timeout: float) -> SerialPort:
    try:
        import serial
    except ImportError as error:
        raise SignTestError(
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
        raise SignTestError(f"cannot open serial port {port}: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run project KD ML-DSA Sign vectors over UART."
    )
    parser.add_argument(
        "--parameter", type=int, choices=sorted(SUPPORTED_PARAMETERS), default=44
    )
    parser.add_argument("--port", help="serial device, e.g. /dev/ttyUSB2")
    parser.add_argument("--commands", type=Path)
    parser.add_argument(
        "--benchmark-cases", type=int,
        help="generate this many deterministic profiling cases instead of using a command file",
    )
    parser.add_argument(
        "--benchmark-start", type=int, default=0,
        help="zero-based generated case index used with --benchmark-cases",
    )
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
            raise SignTestError("timeout must be positive and startup delay nonnegative")
        if args.cpu_mhz is not None and (
            not math.isfinite(args.cpu_mhz) or args.cpu_mhz <= 0
        ):
            raise SignTestError("cpu-mhz must be finite and positive")
        if args.commands is not None and args.benchmark_cases is not None:
            raise SignTestError("--commands and --benchmark-cases cannot be used together")
        if args.benchmark_cases is None and args.benchmark_start != 0:
            raise SignTestError("--benchmark-start requires --benchmark-cases")
        if args.benchmark_cases is not None:
            inputs = generate_benchmark_inputs(
                args.parameter, args.benchmark_cases, args.benchmark_start
            )
        else:
            command_path = (
                args.commands or SCRIPT_DIR / f"sign_commands_{args.parameter}.txt"
            )
            inputs = load_inputs(command_path, args.parameter)
        vectors = build_golden(args.parameter, inputs)
        print(f"Built {len(vectors)} software-reference golden case(s)")
        if args.golden_only:
            return 0
        if args.port is None:
            raise SignTestError("specify --port, or use --golden-only")
        serial_port = open_serial(args.port, args.baud_rate, args.timeout)
        try:
            time.sleep(args.startup_delay)
            serial_port.reset_input_buffer()
            run_vectors(serial_port, args.parameter, vectors, args.timeout, args.cpu_mhz)
        finally:
            serial_port.close()
        print(f"PASS: all ML-DSA-{args.parameter} Sign cases matched")
        return 0
    except SignTestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
