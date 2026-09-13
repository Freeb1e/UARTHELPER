#!/usr/bin/env python3
"""Run only the official 100-record FrodoKEM-SHAKE KAT for each parameter."""

import argparse
from collections import Counter
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from run_board_tests import (
    ROOT, SIZES, PARAMETERS, OPERATIONS, DEFAULT_OPENOCD, build_requests,
    compare_response, firmware_path, hex_bytes, receive, save_json, upload,
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_kat(path, parameter):
    records = []
    current = {}
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        if not separator:
            raise ValueError(f"{path}: invalid KAT line")
        if key == "count" and current:
            records.append(current)
            current = {}
        if key in current:
            raise ValueError(f"{path}: duplicate {key}")
        current[key] = value
    if current:
        records.append(current)
    if not records:
        raise ValueError(f"{path}: no KAT records")
    for index, record in enumerate(records):
        if set(record) != {"count", "seed", "pk", "sk", "ct", "ss"}:
            raise ValueError(f"{path}: incomplete KAT record")
        if int(record["count"]) != index:
            raise ValueError(f"{path}: nonsequential KAT count")
        hex_bytes(record["seed"], 48, "seed")
        for short, field in (("pk", "public_key"), ("sk", "secret_key"),
                             ("ct", "ciphertext"), ("ss", "shared_secret")):
            hex_bytes(record[short], SIZES[parameter][field], short)
    return records


def load_rng(reference_root, build_dir):
    library = build_dir / "frodo_kat_rng.so"
    subprocess.run([
        "cc", "-shared", "-fPIC", "-O2", "-DNIX", "-D_AMD64_",
        "-D_REFERENCE_", "-D_SHAKE128_FOR_A_",
        str(reference_root / "FrodoKEM/tests/rng.c"),
        str(reference_root / "common/aes/aes_c.c"), "-o", str(library),
    ], check=True, capture_output=True, text=True)
    rng = ctypes.CDLL(str(library))
    pointer = ctypes.POINTER(ctypes.c_ubyte)
    rng.randombytes_init.argtypes = (pointer, pointer, ctypes.c_int)
    rng.randombytes_init.restype = None
    rng.randombytes.argtypes = (pointer, ctypes.c_ulonglong)
    rng.randombytes.restype = ctypes.c_int
    return rng


def kat_randomness(rng, seed, parameter):
    seed_buffer = (ctypes.c_ubyte * 48).from_buffer_copy(bytes.fromhex(seed))
    rng.randombytes_init(seed_buffer, None, 256)
    outputs = []
    for field in ("keygen_randomness", "encaps_randomness"):
        length = SIZES[parameter][field]
        output = (ctypes.c_ubyte * length)()
        if rng.randombytes(output, length) != 0:
            raise ValueError("reference randombytes failed")
        outputs.append(bytes(output).hex().upper())
    return outputs


def complete_requests(parameter, case, source):
    for field, size in SIZES[parameter].items():
        hex_bytes(case[field], size, field)
    pk = bytes.fromhex(case["public_key"])
    sk = bytes.fromhex(case["secret_key"])
    security = SIZES[parameter]["shared_secret"]
    shake = hashlib.shake_128 if parameter == 640 else hashlib.shake_256
    pkh = shake(pk).digest(security)
    if pkh.hex().upper() != case["public_key_hash"].upper():
        raise ValueError("PKH reference self-check failed")
    if sk[security:security + len(pk)] != pk or sk[-security:] != pkh:
        raise ValueError("SK/PK reference self-check failed")
    commands = {
        "keygen": (f"KEYGEN {parameter} 1 1 {case['keygen_randomness']}",
                   {"PK": case["public_key"], "PKH": case["public_key_hash"]}),
        "encaps": (f"ENCAPS {parameter} 1 1 {case['public_key']} {case['encaps_randomness']}",
                   {"CT": case["ciphertext"], "SS": case["shared_secret"]}),
        "decaps": (f"DECAPS {parameter} 1 1 {case['secret_key']} {case['ciphertext']}",
                   {"SS": case["shared_secret"], "FAIL_MASK": "0"}),
    }
    return [dict(parameter=parameter, operation=operation, source=source,
                 case=case["index"], kind="valid", command=command, expected=expected)
            for operation, (command, expected) in commands.items()]


def inventory(reference_root, build_dir):
    sources = {}
    requests = []
    sys.path.insert(0, str(reference_root / "FrodoKEM/python3"))
    from nist_kat import NISTKAT
    rng = load_rng(reference_root, build_dir)
    for path in (reference_root / "FrodoKEM/tests/rng.c",
                 reference_root / "FrodoKEM/tests/rng.h",
                 reference_root / "common/aes/aes_c.c",
                 reference_root / "FrodoKEM/python3/nist_kat.py"):
        sources[str(path.resolve())] = digest(path)
    for parameter in PARAMETERS:
        size = SIZES[parameter]
        path = reference_root / "FrodoKEM/KAT" / f"PQCkemKAT_{size['secret_key']}_shake.rsp"
        source = str(path.resolve())
        sources[source] = digest(path)
        records = read_kat(path, parameter)
        if len(records) != 100:
            raise ValueError(f"{path}: expected all 100 official KAT records")
        for record in records:
            kg_random, enc_random = kat_randomness(rng, record["seed"], parameter)
            if record["count"] == "0":
                known = NISTKAT.NISTRNG()
                if known.randombytes(size["keygen_randomness"]).hex().upper() != kg_random:
                    raise ValueError("official RNG KeyGen count-0 check failed")
                if known.randombytes(size["encaps_randomness"]).hex().upper() != enc_random:
                    raise ValueError("official RNG Encaps count-0 check failed")
            pk = bytes.fromhex(record["pk"])
            shake = hashlib.shake_128 if parameter == 640 else hashlib.shake_256
            case = dict(index=int(record["count"]), public_key=record["pk"],
                        secret_key=record["sk"], ciphertext=record["ct"],
                        shared_secret=record["ss"], keygen_randomness=kg_random,
                        encaps_randomness=enc_random,
                        public_key_hash=shake(pk).hexdigest(size["shared_secret"]).upper())
            requests.extend(complete_requests(parameter, case, source))
    requests.sort(key=lambda r: (r["parameter"], OPERATIONS.index(r["operation"]),
                                r["case"]))
    return requests, sources


STAGE_FIELDS = {
    "keygen": {"PK": "pk", "PKH": "pkh"},
    "encaps": {"CT": "ct", "SS": "ss"},
    "decaps": {"SS": "ss", "FAIL_MASK": "fail_mask"},
}


def export_stage_files(requests, destination):
    artifacts = {}
    for parameter in PARAMETERS:
        for operation in OPERATIONS:
            batch = [r for r in requests if r["parameter"] == parameter
                     and r["operation"] == operation]
            if not batch:
                continue
            directory = destination / f"FRODO{operation.upper()}"
            directory.mkdir(parents=True, exist_ok=True)
            outputs = {
                f"{operation}_commands_{parameter}.txt":
                    "".join(r["command"] + "\n" for r in batch),
                f"cases_{parameter}.jsonl": "".join(json.dumps(
                    dict(line=index + 1, source=r["source"], case=r["case"],
                         kind=r["kind"])) + "\n" for index, r in enumerate(batch)),
            }
            for field, name in STAGE_FIELDS[operation].items():
                outputs[f"{name}_ref_{parameter}.txt"] = "".join(
                    r["expected"][field].upper() + "\n" for r in batch)
            for name, content in outputs.items():
                path = directory / name
                path.write_text(content, encoding="ascii")
                artifacts[str(path.resolve())] = digest(path)
    return artifacts


def read_stage_files(directory, parameter, operation):
    commands = (directory / f"{operation}_commands_{parameter}.txt").read_text().splitlines()
    references = {field: (directory / f"{name}_ref_{parameter}.txt").read_text().splitlines()
                  for field, name in STAGE_FIELDS[operation].items()}
    metadata = [json.loads(line) for line in
                (directory / f"cases_{parameter}.jsonl").read_text().splitlines()]
    if not commands or any(len(lines) != len(commands) for lines in
                           [metadata, *references.values()]):
        raise ValueError(f"{directory}: command/reference line counts differ")
    requests = []
    for index, command in enumerate(commands):
        fields = command.split()
        expected_count = 5 if operation == "keygen" else 6
        if len(fields) != expected_count or fields[:4] != [
                operation.upper(), str(parameter), "1", "1"]:
            raise ValueError(f"{directory}:{index + 1}: invalid command")
        inputs = {"keygen": ("keygen_randomness",),
                  "encaps": ("public_key", "encaps_randomness"),
                  "decaps": ("secret_key", "ciphertext")}[operation]
        for value, name in zip(fields[4:], inputs):
            hex_bytes(value, SIZES[parameter][name], name)
        expected = {field: lines[index] for field, lines in references.items()}
        for field, value in expected.items():
            if field == "FAIL_MASK":
                if value not in {"0", "255"}:
                    raise ValueError("invalid reference failure mask")
            else:
                name = {"PK": "public_key", "PKH": "public_key_hash",
                        "CT": "ciphertext", "SS": "shared_secret"}[field]
                hex_bytes(value, SIZES[parameter][name], field)
        item = metadata[index]
        if item["line"] != index + 1:
            raise ValueError("case index does not match command line")
        requests.append(dict(parameter=parameter, operation=operation,
                             command=command, expected=expected, source=item["source"],
                             case=item["case"], kind=item["kind"]))
    return requests


def request_key(request):
    return (request["parameter"], request["operation"], request["source"],
            request["case"], request["kind"])


def verified_prior_results(path, requests):
    expected = {request_key(request): request for request in requests}
    reuse = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        record = json.loads(line)
        key = request_key(record)
        if record.get("status") != "PASS" or key not in expected:
            continue
        request = expected[key]
        payload = (request["command"] + "\n").encode("ascii")
        if record["command_sha256"] != hashlib.sha256(payload).hexdigest():
            raise ValueError("previous command does not match current KAT")
        if record["firmware_sha256"] != digest(firmware_path(
                request["operation"], request["parameter"])):
            raise ValueError("previous firmware differs from current firmware")
        compare_response(record["response"], request["expected"])
        if key in reuse:
            raise ValueError("duplicate previously passed KAT result")
        record["reused_from"] = dict(path=str(path.resolve()), line=line_number)
        reuse[key] = record
    return reuse


def execute(args, requests, summary, reuse=None):
    reuse = {} if reuse is None else reuse
    import serial
    counts = Counter()
    with serial.Serial(args.port, 115200, timeout=0.1, write_timeout=120,
                       exclusive=True) as port, (args.results / "results.jsonl").open(
                           "w", encoding="ascii") as records:
        for parameter in PARAMETERS:
            for operation in OPERATIONS:
                batch = [r for r in requests if r["parameter"] == parameter
                         and r["operation"] == operation]
                if not batch:
                    continue
                reused = [reuse[request_key(r)] for r in batch if request_key(r) in reuse]
                for record in reused:
                    records.write(json.dumps(record) + "\n")
                    counts[f"{parameter}_{operation}"] += 1
                if reused:
                    records.flush()
                    summary.update(passed=sum(counts.values()), batches=dict(counts))
                    save_json(args.results / "summary.json", summary)
                    print(f"REUSED Frodo-{parameter} {operation}: {len(reused)} verified KATs",
                          flush=True)
                batch = [r for r in batch if request_key(r) not in reuse]
                if not batch:
                    continue
                with (args.results / f"{operation}_{parameter}.txt").open(
                        "w", encoding="ascii") as log:
                    firmware_hash = upload(args, operation, parameter, log)
                    time.sleep(1)
                    startup = port.read(port.in_waiting).decode("ascii")
                    log.write(startup)
                    version = 2 if operation == "keygen" else 1
                    if f"READY FRODO_{operation.upper()} {version}" not in startup:
                        raise ValueError(f"missing READY: {startup!r}")
                    print(f"START Frodo-{parameter} {operation}: {len(batch)} requests", flush=True)
                    for index, request in enumerate(batch):
                        record = {k: v for k, v in request.items()
                                  if k not in {"command", "expected"}}
                        payload = (request["command"] + "\n").encode("ascii")
                        record.update(firmware_sha256=firmware_hash,
                                      command_sha256=hashlib.sha256(payload).hexdigest(),
                                      timestamp=datetime.now(timezone.utc).isoformat())
                        try:
                            log.write("TX " + request["command"] + "\n")
                            log.flush()
                            if port.write(payload) != len(payload):
                                raise ValueError("UART short write")
                            port.flush()
                            response = receive(port, parameter, 120, log)
                            record["response"] = response
                            record["cycles"] = compare_response(response, request["expected"])
                            record["status"] = "PASS"
                            counts[f"{parameter}_{operation}"] += 1
                        except Exception as error:
                            record.update(status="FAIL", error=str(error))
                            raise
                        finally:
                            record.setdefault("status", "INTERRUPTED")
                            records.write(json.dumps(record) + "\n")
                            records.flush()
                            summary.update(passed=sum(counts.values()), batches=dict(counts),
                                           last_record={k: v for k, v in record.items()
                                                        if k not in {"response", "cycles"}})
                            save_json(args.results / "summary.json", summary)
                        if (index + 1) % 5 == 0 or index + 1 == len(batch):
                            print(f"PASS Frodo-{parameter} {operation} {index + 1}/{len(batch)} "
                                  f"overall={sum(counts.values())}/{len(requests)}", flush=True)
    if sum(counts.values()) != len(requests):
        raise ValueError("completed count does not match inventory")
    summary.update(status="PASS", completed_at=datetime.now(timezone.utc).isoformat())
    save_json(args.results / "summary.json", summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--port", default="/dev/ttyUSB2")
    parser.add_argument("--openocd", type=Path, default=DEFAULT_OPENOCD)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--reuse-results", type=Path,
                        help="reuse only fully verified matching KAT outcomes")
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=False)
    summary = dict(status="RUNNING", started_at=datetime.now(timezone.utc).isoformat(),
                   port=args.port, baud_rate=115200, passed=0, suite="official-shake-kat")
    try:
        with tempfile.TemporaryDirectory(prefix="frodo-kat-") as build:
            requests, sources = inventory(args.reference_root, Path(build))
        artifacts = export_stage_files(requests, ROOT / "UARTHELPER")
        from_files = []
        for parameter in PARAMETERS:
            for operation in OPERATIONS:
                from_files.extend(read_stage_files(
                    ROOT / "UARTHELPER" / f"FRODO{operation.upper()}", parameter, operation))
        if from_files != requests:
            raise ValueError("stage files do not match official KAT requests")
        prepared = dict(source_sha256=sources, stage_files_sha256=artifacts,
                        total=len(requests), batches=dict(Counter(
                            f"{r['parameter']}_{r['operation']}" for r in requests)))
        save_json(args.results / "inventory.json", prepared)
        reuse = verified_prior_results(args.reuse_results, requests) if args.reuse_results else {}
        summary.update(total=len(requests), reused=len(reuse))
        save_json(args.results / "summary.json", summary)
        print(f"Prepared {len(requests)} official KAT requests; "
              f"{len(reuse)} verified prior results", flush=True)
        if args.prepare_only:
            summary["status"] = "PREPARED"
            save_json(args.results / "summary.json", summary)
        else:
            execute(args, from_files, summary, reuse)
    except KeyboardInterrupt:
        summary.update(status="INTERRUPTED")
        save_json(args.results / "summary.json", summary)
        return 130
    except Exception as error:
        summary.update(status="FAIL", error=str(error))
        save_json(args.results / "summary.json", summary)
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
