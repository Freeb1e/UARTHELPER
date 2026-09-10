#!/usr/bin/env python3
"""Check Scloud SM3 Decaps with official SK/CT KATs and implicit rejection."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys
import time

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "SCLOUDENCAPS"))
from run_encaps_tests import load_kats  # noqa: E402
from run_keygen_tests import (  # noqa: E402
    KeygenTestError, load_vectors, open_serial, print_cycle_report,
)


@dataclass(frozen=True)
class Case:
    count: int
    kind: str
    sk: bytes
    ct: bytes
    ss: bytes
    fail_mask: int


def load_cases(path: Path) -> tuple[int, list[Case]]:
    parameter, vectors = load_kats(path)
    _, keys = load_vectors(path)
    expected_sk = {128: 7440, 192: 13872, 256: 19680}[parameter]
    cases = []
    for vector, key in zip(vectors, keys, strict=True):
        if len(key.secret_key) != expected_sk:
            raise KeygenTestError(f"Count {key.count}: wrong SK length")
        cases.append(Case(vector.count, "valid", key.secret_key, vector.ct, vector.ss, 0))
    first = cases[0]
    modified = bytearray(first.ct)
    modified[-1] ^= 0x80
    # Low SM3 parameters need at most one 32-byte block of K's labeled XOF.
    fallback = hashlib.new("sm3", b"K" + first.sk[-64:] + modified + b"\0\0\0\1").digest()
    cases.append(Case(first.count, "tampered", first.sk, bytes(modified),
                      fallback[:parameter // 8], 255))
    return parameter, cases


def build_commands(parameter: int, cases: list[Case]) -> list[bytes]:
    return [f"DECAPS {parameter} {case.sk.hex()} {case.ct.hex()}\n".encode("ascii")
            for case in cases]


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
            required = {"SS", "FAIL_MASK", "CPU_HZ", "CYCLES_ALGORITHM_TOTAL"}
            if not ok or not required <= fields.keys():
                raise KeygenTestError("incomplete board response")
            try:
                ss = bytes.fromhex(fields["SS"])
                mask = int(fields["FAIL_MASK"])
                hz = int(fields["CPU_HZ"])
                cycles = {k: int(v) for k, v in fields.items() if k.startswith("CYCLES_")}
                if hz <= 0 or mask not in (0, 255) or any(v < 0 for v in cycles.values()):
                    raise ValueError("invalid frequency, mask or cycles")
                return ss, mask, cycles, hz
            except ValueError as error:
                raise KeygenTestError(f"invalid board response: {error}") from error
        elif "=" in line:
            name, value = line.split("=", 1)
            if name in fields:
                raise KeygenTestError(f"duplicate board field {name}")
            fields[name] = value
    raise KeygenTestError("timed out waiting for END")


def run_cases(port, parameter, cases, commands, timeout):
    for i, (case, command) in enumerate(zip(cases, commands, strict=True), 1):
        print(f"[{i}/{len(cases)}] Count={case.count} {case.kind} TX DECAPS <SK> <CT>", flush=True)
        if port.write(command) != len(command):
            raise KeygenTestError("UART short write")
        port.flush()
        ss, mask, cycles, hz = receive_result(port, parameter, timeout)
        print_cycle_report(cycles, hz / 1_000_000)
        if ss != case.ss or mask != case.fail_mask:
            raise KeygenTestError(f"Count {case.count} {case.kind}: SS match={ss == case.ss}, FAIL_MASK={mask}")
        print(f"  PASS {case.kind} SS={len(ss)} bytes FAIL_MASK={mask} CPU_HZ={hz}", flush=True)


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
        parameter, cases = load_cases(args.vectors)
        commands = build_commands(parameter, cases)
        if args.commands_out:
            args.commands_out.write_bytes(b"".join(commands))
            print(f"Wrote {len(commands)} commands to {args.commands_out}")
        if args.port:
            port = open_serial(args.port, 115200, args.timeout)
            try:
                time.sleep(1)
                port.reset_input_buffer()
                run_cases(port, parameter, cases, commands, args.timeout)
            finally:
                port.close()
            print(f"PASS: Scloud+{parameter}-SM3 Decaps: {len(cases)-1} valid KATs and 1 tampered case matched")
        return 0
    except (KeygenTestError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
