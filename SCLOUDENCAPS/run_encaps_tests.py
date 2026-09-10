#!/usr/bin/env python3
"""Replay official Scloud SM3 Encaps KATs with host-derived messages."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "SCLOUDKEYGEN"))
from run_keygen_tests import (  # noqa: E402
    PROJECT_ROOT, KeygenTestError, load_vectors, open_serial, print_cycle_report,
)


@dataclass(frozen=True)
class Vector:
    count: int
    seed: bytes
    pk: bytes
    ct: bytes
    ss: bytes


def load_kats(path: Path) -> tuple[int, list[Vector]]:
    parameter, keys = load_vectors(path)
    records = []
    fields = {}
    for line in path.read_text(encoding="ascii").splitlines() + [""]:
        if not line.strip():
            if fields:
                records.append(fields)
                fields = {}
            continue
        name, _, value = line.partition(" = ")
        if name in fields:
            raise KeygenTestError(f"duplicate KAT field {name}")
        fields[name] = value
    result = []
    lengths = {128: (6096, 6160), 192: (11456, 12645), 256: (16296, 17925)}
    for key, record in zip(keys, records, strict=True):
        try:
            ct, ss = bytes.fromhex(record["CT"]), bytes.fromhex(record["SS"])
            if len(ct) != int(record["CT_Len"]) or len(ss) != int(record["SS_Len"]):
                raise ValueError("CT/SS length mismatch")
            if (len(key.public_key), len(ct)) != lengths[parameter] or len(ss) != parameter // 8:
                raise ValueError("unexpected parameter object sizes")
        except (KeyError, ValueError) as error:
            raise KeygenTestError(f"Count {key.count}: invalid Encaps KAT: {error}") from error
        result.append(Vector(key.count, key.seed, key.public_key, ct, ss))
    return parameter, result


def build_commands(parameter: int, vectors: list[Vector]) -> list[bytes]:
    reference = PROJECT_ROOT / "third_party/Scloud+/Implementations/_shared/api_pkc"
    width = parameter // 8
    try:
        with tempfile.TemporaryDirectory(prefix="scloud-encaps-") as directory:
            helper = Path(directory) / "derive_message"
            subprocess.run(["cc", "-std=c11", "-O2", "-I", str(reference),
                            str(SCRIPT_DIR / "derive_message.c"), str(reference / "drng.c"),
                            "-o", str(helper)], check=True, capture_output=True)
            data = subprocess.run([str(helper), str(width)],
                                  input=b"".join(v.seed for v in vectors),
                                  check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise KeygenTestError(f"host DRNG failed: {error}") from error
    if len(data) != len(vectors) * width:
        raise KeygenTestError("host DRNG returned wrong message length")
    return [f"ENCAPS {parameter} {v.pk.hex()} {data[i*width:(i+1)*width].hex()}\n".encode("ascii")
            for i, v in enumerate(vectors)]


def receive_result(port, parameter: int, timeout: float):
    deadline = time.monotonic() + timeout
    fields = {}
    ok = False
    while time.monotonic() < deadline:
        raw = port.readline()
        if not raw:
            continue
        try:
            line = raw.decode("ascii").strip()
        except UnicodeError as error:
            raise KeygenTestError("non-ASCII board response") from error
        if not line:
            continue
        if line.startswith("ERROR"):
            raise KeygenTestError(line)
        if line == f"OK PARA={parameter} FAMILY=SM3":
            ok = True
        elif line == "END":
            if not ok or not {"CT", "SS", "CPU_HZ", "CYCLES_ALGORITHM_TOTAL"} <= fields.keys():
                raise KeygenTestError("incomplete board response")
            try:
                ct, ss = bytes.fromhex(fields["CT"]), bytes.fromhex(fields["SS"])
                hz = int(fields["CPU_HZ"])
                cycles = {k: int(v) for k, v in fields.items() if k.startswith("CYCLES_")}
                if hz <= 0 or any(v < 0 for v in cycles.values()):
                    raise ValueError("invalid frequency or cycles")
                return ct, ss, cycles, hz
            except ValueError as error:
                raise KeygenTestError(f"invalid board response: {error}") from error
        elif "=" in line:
            name, value = line.split("=", 1)
            if name in fields:
                raise KeygenTestError(f"duplicate board field {name}")
            fields[name] = value
    raise KeygenTestError("timed out waiting for END")


def run_vectors(port, parameter, vectors, commands, timeout):
    for i, (vector, command) in enumerate(zip(vectors, commands, strict=True), 1):
        print(f"[{i}/{len(vectors)}] Count={vector.count} TX ENCAPS <PK> <m>", flush=True)
        if port.write(command) != len(command):
            raise KeygenTestError("UART short write")
        port.flush()
        ct, ss, cycles, hz = receive_result(port, parameter, timeout)
        print_cycle_report(cycles, hz / 1_000_000)
        if ct != vector.ct or ss != vector.ss:
            raise KeygenTestError(f"Count {vector.count}: CT match={ct == vector.ct}, SS match={ss == vector.ss}")
        print(f"  PASS CT={len(ct)} bytes SS={len(ss)} bytes CPU_HZ={hz}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, required=True)
    parser.add_argument("--port")
    parser.add_argument("--commands-out", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args(argv)
    try:
        if not args.port and not args.commands_out:
            raise KeygenTestError("specify --port or --commands-out")
        if not 0 < args.timeout < float("inf"):
            raise KeygenTestError("timeout must be finite and positive")
        parameter, vectors = load_kats(args.vectors)
        commands = build_commands(parameter, vectors)
        if args.commands_out:
            args.commands_out.write_bytes(b"".join(commands))
            print(f"Wrote {len(commands)} commands to {args.commands_out}")
        if args.port:
            port = open_serial(args.port, 115200, args.timeout)
            try:
                time.sleep(1)
                port.reset_input_buffer()
                run_vectors(port, parameter, vectors, commands, args.timeout)
            finally:
                port.close()
            print(f"PASS: all {len(vectors)} Scloud+{parameter}-SM3 Encaps vectors matched")
        return 0
    except (KeygenTestError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
