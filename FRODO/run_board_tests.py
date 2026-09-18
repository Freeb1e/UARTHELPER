#!/usr/bin/env python3
"""Generate reference vectors and verify all FrodoKEM-SHAKE UART stages."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PARAMETERS = (640, 976, 1344)
SIZES = {
    640: dict(public_key=9616, secret_key=19888, ciphertext=9752,
              public_key_hash=16, shared_secret=16, keygen_randomness=64,
              encaps_randomness=48),
    976: dict(public_key=15632, secret_key=31296, ciphertext=15792,
              public_key_hash=24, shared_secret=24, keygen_randomness=88,
              encaps_randomness=72),
    1344: dict(public_key=21520, secret_key=43088, ciphertext=21696,
               public_key_hash=32, shared_secret=32, keygen_randomness=112,
               encaps_randomness=96),
}
OPERATIONS = ("keygen", "encaps", "decaps")
DEFAULT_OPENOCD = Path("/home/tomoyo/NucleiStudio_IDE_202510-lin64/"
                       "NucleiStudio_IDE_202510/NucleiStudio/toolchain/openocd/bin/openocd")


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def generate(args):
    source = args.reference_root / "FrodoKEM/python3"
    sys.path.insert(0, str(source))
    generator = importlib.import_module("generate_hw_test_vectors")
    reference = generator.load_reference_class()
    seed = bytes.fromhex(args.seed)
    if not seed or args.count < 1:
        raise ValueError("seed must be nonempty and count must be positive")
    args.vectors.mkdir(parents=True, exist_ok=False)
    provenance = {
        "reference_root": str(args.reference_root.resolve()),
        "source_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                          for name in ("generate_hw_test_vectors.py", "frodokem.py")},
        "master_seed": seed.hex().upper(), "count": args.count,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json(args.vectors / "provenance.json", provenance)
    for parameter in args.parameters:
        kem = reference(f"FrodoKEM-{parameter}-SHAKE")
        cases = []
        for index in range(args.count):
            print(f"Generating Frodo-{parameter} case {index + 1}/{args.count}", flush=True)
            case = generator.generate_case(reference, str(parameter), seed, index,
                                           "decaps", True)
            ct = bytearray.fromhex(case["ciphertext"])
            packed_b = SIZES[parameter]["public_key"] - 16
            mutation_index = packed_b + (60 if parameter == 640 else 64)
            ct[mutation_index] ^= 0x80
            sk = bytes.fromhex(case["secret_key"])
            rejected = kem.kem_decaps(sk, bytes(ct))
            security = SIZES[parameter]["shared_secret"]
            fallback = kem.shake(bytes(ct) + sk[:security], security)
            if rejected != fallback:
                raise ValueError("mutated ciphertext did not take implicit rejection")
            case.update(rejected_ciphertext=ct.hex().upper(),
                        rejected_shared_secret=rejected.hex().upper(),
                        mutation_index=mutation_index, mutation_xor=128)
            cases.append(case)
        manifest = {"schema": "frodo-board-v1", "parameter": parameter, "cases": cases}
        save_json(args.vectors / f"frodo_{parameter}.json", manifest)
        for operation in OPERATIONS:
            requests = build_requests(manifest, operation)
            (args.vectors / f"{operation}_commands_{parameter}.txt").write_text(
                "".join(request["command"] + "\n" for request in requests), encoding="ascii")
        print(f"Saved Frodo-{parameter}: {len(cases)} complete reference cases", flush=True)


def hex_bytes(value, size, name):
    if not isinstance(value, str) or len(value) != size * 2:
        raise ValueError(f"{name}: expected {size} bytes")
    result = bytes.fromhex(value)
    if len(result) != size:
        raise ValueError(f"{name}: invalid hex")
    return result


def build_requests(manifest, operation):
    if manifest["schema"] != "frodo-board-v1" or operation not in OPERATIONS:
        raise ValueError("unsupported manifest schema or operation")
    parameter = manifest["parameter"]
    sizes = SIZES[parameter]
    if not manifest["cases"]:
        raise ValueError("empty reference cases")
    requests = []
    for case in manifest["cases"]:
        for field, size in sizes.items():
            hex_bytes(case[field], size, field)
        hex_bytes(case["rejected_ciphertext"], sizes["ciphertext"], "rejected_ciphertext")
        hex_bytes(case["rejected_shared_secret"], sizes["shared_secret"], "rejected_shared_secret")
        if operation == "keygen":
            command = f"KEYGEN {parameter} 1 1 {case['keygen_randomness']}"
            expected = {"PK": case["public_key"], "PKH": case["public_key_hash"]}
        elif operation == "encaps":
            command = (f"ENCAPS {parameter} 1 1 {case['public_key']} "
                       f"{case['encaps_randomness']}")
            expected = {"CT": case["ciphertext"], "SS": case["shared_secret"]}
        else:
            command = (f"DECAPS {parameter} 1 1 {case['secret_key']} "
                       f"{case['ciphertext']}")
            expected = {"SS": case["shared_secret"], "FAIL_MASK": "0"}
        requests.append(dict(case=case["index"], kind="valid",
                             command=command, expected=expected))
        if operation == "decaps":
            requests.append(dict(
                case=case["index"], kind="tampered",
                command=f"DECAPS {parameter} 1 1 {case['secret_key']} {case['rejected_ciphertext']}",
                expected={"SS": case["rejected_shared_secret"], "FAIL_MASK": "255"}))
    return requests


def receive(port, parameter, timeout, transcript):
    deadline = time.monotonic() + timeout
    pending = bytearray()
    fields = {}
    saw_ok = False
    while time.monotonic() < deadline:
        chunk = port.read(max(1, min(port.in_waiting, 65536)))
        if not chunk:
            continue
        pending.extend(chunk)
        while b"\n" in pending:
            raw, _, pending = pending.partition(b"\n")
            line = raw.decode("ascii").strip()
            transcript.write("RX " + line + "\n")
            transcript.flush()
            if line.startswith("ERROR"):
                raise ValueError(f"board returned {line}")
            if line.startswith("OK "):
                if saw_ok or line != f"OK PARA={parameter}":
                    raise ValueError(f"unexpected acknowledgement: {line}")
                saw_ok = True
            elif line == "END":
                if not saw_ok:
                    raise ValueError("END without matching OK")
                return fields
            elif "=" in line:
                name, value = line.split("=", 1)
                if name in fields:
                    raise ValueError(f"duplicate field: {name}")
                fields[name] = value
    if pending:
        transcript.write("PARTIAL_RX " + repr(bytes(pending)) + "\n")
    raise TimeoutError(f"no complete response in {timeout:g}s")


def compare_response(fields, expected):
    for name, reference in expected.items():
        actual = fields.get(name)
        if actual is None:
            raise ValueError(f"missing {name}")
        if name == "FAIL_MASK":
            if actual != reference:
                raise ValueError(f"FAIL_MASK: expected {reference}, got {actual}")
            continue
        actual_bytes = hex_bytes(actual, len(reference) // 2, name)
        reference_bytes = bytes.fromhex(reference)
        if actual_bytes != reference_bytes:
            offset = next(i for i, (a, b) in enumerate(zip(actual_bytes, reference_bytes))
                          if a != b)
            raise ValueError(f"{name} mismatch at byte {offset}: "
                             f"board={actual_bytes[offset]:02X} reference={reference_bytes[offset]:02X}")
    cycles = {name: int(value) for name, value in fields.items() if name.startswith("CYCLES_")}
    if cycles.get("CYCLES_ALGORITHM_TOTAL", 0) <= 0:
        raise ValueError("missing or zero algorithm cycles")
    if any(value < 0 for value in cycles.values()):
        raise ValueError("negative cycle count")
    return cycles


def firmware_path(operation, parameter, firmware_tree="BOARDSW"):
    name = f"frodo_{operation}"
    target = name + (f"_{parameter}" if firmware_tree == "HWDISPLAY" or
                     operation == "decaps" else "")
    return ROOT / "e203_hbirdv2/scripts" / firmware_tree / name / f"{target}.elf"


def upload(args, operation, parameter, transcript):
    firmware = firmware_path(operation, parameter, args.firmware_tree)
    if not firmware.is_file():
        raise ValueError(f"firmware not found: {firmware}")
    config = ROOT / "e203_hbirdv2/scripts/BOARDSW/scloud_encaps/openocd_ilm.cfg"
    command = [str(args.openocd), "-f", str(config),
               "-c", "reset halt", "-c", f"load_image {firmware}",
               "-c", f"verify_image {firmware}",
               "-c", "resume 0x80000000", "-c", "shutdown"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    transcript.write(result.stdout + result.stderr)
    transcript.flush()
    if result.returncode != 0 or "verified" not in result.stdout + result.stderr:
        raise ValueError(f"OpenOCD load/verify failed: {result.stdout}{result.stderr}")
    return hashlib.sha256(firmware.read_bytes()).hexdigest()


def test_board(args):
    import serial

    # Validate every input before resetting the CPU or sending UART commands.
    batches = []
    for parameter in args.parameters:
        manifest = json.loads((args.vectors / f"frodo_{parameter}.json").read_text())
        if manifest["parameter"] != parameter:
            raise ValueError("manifest parameter does not match filename")
        for operation in args.operations:
            batches.append((parameter, operation, build_requests(manifest, operation)))
    args.results.mkdir(parents=True, exist_ok=False)
    report = dict(started_at=datetime.now(timezone.utc).isoformat(), port=args.port,
                  baud_rate=args.baud_rate, firmware_tree=args.firmware_tree,
                  vectors=str(args.vectors.resolve()), results=[])
    report_path = args.results / "results.json"
    save_json(report_path, report)
    with serial.Serial(args.port, args.baud_rate, timeout=0.1,
                       write_timeout=args.timeout, exclusive=True) as port:
        for parameter, operation, requests in batches:
            print(f"Frodo-{parameter} {operation}: loading firmware", flush=True)
            with (args.results / f"{operation}_{parameter}.txt").open("w", encoding="ascii") as log:
                firmware_hash = upload(args, operation, parameter, log)
                time.sleep(1)
                startup = port.read(port.in_waiting).decode("ascii")
                log.write(startup)
                version = 2 if operation == "keygen" else 1
                if f"READY FRODO_{operation.upper()} {version}" not in startup:
                    raise ValueError(f"missing firmware READY banner: {startup!r}")
                for request in requests:
                    record = dict(parameter=parameter, operation=operation,
                                  case=request["case"], kind=request["kind"],
                                  firmware_sha256=firmware_hash)
                    report["results"].append(record)
                    try:
                        payload = (request["command"] + "\n").encode("ascii")
                        log.write("TX " + request["command"] + "\n")
                        log.flush()
                        written = port.write(payload)
                        if written != len(payload):
                            raise ValueError(f"short write: {written}/{len(payload)}")
                        port.flush()
                        fields = receive(port, parameter, args.timeout, log)
                        record["response"] = fields
                        record["cycles"] = compare_response(fields, request["expected"])
                        record["status"] = "PASS"
                        print(f"  case {request['case']} {request['kind']}: PASS "
                              f"cycles={record['cycles']['CYCLES_ALGORITHM_TOTAL']}", flush=True)
                    except Exception as error:
                        record.update(status="FAIL", error=str(error))
                        raise
                    finally:
                        save_json(report_path, report)
    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    save_json(report_path, report)
    print(f"PASS: {len(report['results'])} board requests; report {report_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    gen = subparsers.add_parser("generate")
    gen.add_argument("--reference-root", type=Path, required=True)
    gen.add_argument("--seed", default="000102030405060708090A0B0C0D0E0F"
                     "101112131415161718191A1B1C1D1E1F")
    gen.add_argument("--count", type=int, default=3)
    run = subparsers.add_parser("test")
    run.add_argument("--port", required=True)
    run.add_argument("--baud-rate", type=int, default=115200)
    run.add_argument("--timeout", type=float, default=120)
    run.add_argument("--openocd", type=Path, default=DEFAULT_OPENOCD)
    run.add_argument("--firmware-tree", choices=("BOARDSW", "HWDISPLAY"),
                     default="BOARDSW")
    run.add_argument("--results", type=Path, required=True)
    run.add_argument("--operations", nargs="+", choices=OPERATIONS, default=OPERATIONS)
    for command in (gen, run):
        command.add_argument("--vectors", type=Path, required=True)
        command.add_argument("--parameters", nargs="+", type=int,
                             choices=PARAMETERS, default=PARAMETERS)
    args = parser.parse_args()
    try:
        if args.action == "generate":
            generate(args)
        else:
            if args.timeout <= 0 or args.baud_rate <= 0:
                raise ValueError("timeout and baud rate must be positive")
            test_board(args)
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
