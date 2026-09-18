#!/usr/bin/env python3
"""Verify one Scloud+ SM3 KAT per HWDISPLAY image on the physical board."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
for directory in ("SCLOUDKEYGEN", "SCLOUDENCAPS", "SCLOUDDECAPS"):
    sys.path.insert(0, str(ROOT / "UARTHELPER" / directory))

import run_keygen_tests as keygen  # noqa: E402
import run_encaps_tests as encaps  # noqa: E402
import run_decaps_tests as decaps  # noqa: E402

OPENOCD = Path("/home/tomoyo/NucleiStudio_IDE_202510-lin64/"
               "NucleiStudio_IDE_202510/NucleiStudio/toolchain/openocd/bin/openocd")
CONFIG = ROOT / "e203_hbirdv2/scripts/HWDISPLAY/scloud_encaps/openocd_ilm.cfg"
STAGES = {
    "keygen": ("EXPAND_F", "SAMPLE_S", "SAMPLE_E", "A_S_PLUS_E", "HASH_PK"),
    "encaps": ("HASHES_H_G_F", "SAMPLE_SP", "SAMPLE_E1_E2",
               "TILED_SA_E1_PACK_C1", "TILED_IMPORT_B_SB_E2", "ENCODE_PACK_C2", "HASH_K"),
    "decaps": ("DECRYPT", "REENCRYPT_COMPARE", "SELECT", "HASH_K"),
}
LOW_STAGES = {
    "keygen": ("EXPAND_F", "SAMPLE_S", "SAMPLE_E", "A_S_PLUS_E",
               "MOVE_B_TO_DTCM", "COMPACT_B", "PACK_PK", "HASH_PK", "SERIALIZE_SK"),
    "encaps": ("HASHES_H_G_F", "SAMPLE_SP", "SAMPLE_E1_E2", "SA_PLUS_E1",
               "EXPORT_PACK_C1", "IMPORT_B", "SB_PLUS_E2", "ENCODE_PACK_C2", "HASH_K"),
}


def firmware_path(operation, parameter):
    app = f"scloud{'512' if parameter == 512 else ''}_{operation}"
    target = app if parameter == 512 else f"{app}_{parameter}"
    return ROOT / "e203_hbirdv2/scripts/HWDISPLAY" / app / f"{target}.elf"


def prepare(operation, parameter):
    vectors_path = (ROOT / "third_party/Scloud+/Test_Vectors" /
                    f"KAT_KEM_Scloudplus-{parameter}-SM3-packed10.txt")
    command_path = (ROOT / "UARTHELPER" / f"SCLOUD{operation.upper()}" /
                    f"{operation}_commands_{parameter}.txt")
    with command_path.open(encoding="ascii") as stream:
        command = next((line.encode("ascii") for line in stream
                        if line.startswith(f"{operation.upper()} {parameter} ")), None)
    if command is None:
        raise ValueError(f"missing {operation} {parameter} command in {command_path}")
    if operation == "keygen":
        _, vectors = keygen.load_vectors(vectors_path)
        cases = vectors[:1]
        commands = [command]
    elif operation == "encaps":
        _, vectors = encaps.load_kats(vectors_path)
        cases = vectors[:1]
        commands = [command]
    else:
        _, cases_all = decaps.load_cases(vectors_path)
        cases = [cases_all[0], cases_all[-1]]
        commands = [command, *decaps.build_commands(parameter, cases[-1:])]
    if len(cases) != len(commands) or cases[0].count != 0:
        raise ValueError("expected Count=0 and matching commands")
    fields = command.decode("ascii").split()
    if operation == "encaps" and bytes.fromhex(fields[2]) != cases[0].pk:
        raise ValueError("prepared Encaps public key does not match KAT Count=0")
    if operation == "decaps" and (bytes.fromhex(fields[2]) != cases[0].sk or
                                  bytes.fromhex(fields[3]) != cases[0].ct):
        raise ValueError("prepared Decaps input does not match KAT Count=0")
    return vectors_path, list(zip(cases, commands))


def upload(openocd, firmware, log):
    if not firmware.is_file():
        raise ValueError(f"firmware missing: {firmware}")
    command = [str(openocd), "-f", str(CONFIG), "-c", "reset halt",
               "-c", f"load_image {firmware}",
               "-c", f"verify_image {firmware}",
               "-c", "resume 0x80000000", "-c", "shutdown"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    output = result.stdout + result.stderr
    log.write(output)
    log.flush()
    if result.returncode != 0 or "verified" not in output:
        raise ValueError(f"JTAG load/verify failed: {output}")


class LoggedPort:
    def __init__(self, port, log):
        self.port = port
        self.log = log
        self.fields = {}

    def write(self, payload):
        self.log.write("TX " + payload.decode("ascii"))
        self.log.flush()
        return self.port.write(payload)

    def flush(self):
        self.port.flush()

    def readline(self):
        raw = self.port.readline()
        if raw:
            line = raw.decode("ascii", errors="replace").strip()
            self.log.write("RX " + line + "\n")
            self.log.flush()
            if "=" in line:
                name, value = line.split("=", 1)
                self.fields[name] = value
        return raw


def verify(operation, parameter, case, command, port):
    port.fields = {}
    if port.write(command) != len(command):
        raise ValueError("short UART write")
    port.flush()
    if operation == "keygen":
        pk, sk, cycles = keygen.receive_result(port, parameter, 120)
        expected = {"PK": case.public_key, "SK": case.secret_key}
        actual = {"PK": pk, "SK": sk}
    elif operation == "encaps":
        ct, ss, cycles, _ = encaps.receive_result(port, parameter, 120)
        expected = {"CT": case.ct, "SS": case.ss}
        actual = {"CT": ct, "SS": ss}
    else:
        ss, mask, cycles, _ = decaps.receive_result(port, parameter, 120)
        expected = {"SS": case.ss, "FAIL_MASK": case.fail_mask}
        actual = {"SS": ss, "FAIL_MASK": mask}
    for name, reference in expected.items():
        if actual[name] != reference:
            raise ValueError(f"{name} mismatch for Count={case.count}")
    stages = LOW_STAGES.get(operation, STAGES[operation]) if parameter != 512 else STAGES[operation]
    expected_cycles = {f"CYCLES_{name}" for name in stages} | {"CYCLES_ALGORITHM_TOTAL"}
    if set(cycles) != expected_cycles or any(value < 0 for value in cycles.values()):
        raise ValueError(f"unexpected cycle fields: {cycles}")
    if cycles["CYCLES_ALGORITHM_TOTAL"] < sum(cycles[name] for name in expected_cycles
                                               if name != "CYCLES_ALGORITHM_TOTAL"):
        raise ValueError("stage cycles exceed total")
    return {
        "count": case.count, "kind": getattr(case, "kind", "valid"),
        "command_sha256": hashlib.sha256(command).hexdigest(),
        "checked_fields": list(expected),
        "output_sha256": {name: hashlib.sha256(value).hexdigest()
                          for name, value in actual.items() if isinstance(value, bytes)},
        "fail_mask": actual.get("FAIL_MASK"),
        "cpu_hz": int(port.fields["CPU_HZ"]) if "CPU_HZ" in port.fields else None,
        "cycles": cycles, "status": "PASS",
    }


def run(args):
    vectors, cases = prepare(args.operation, args.parameter)
    firmware = firmware_path(args.operation, args.parameter)
    if not firmware.is_file():
        raise ValueError(f"firmware missing: {firmware}")
    args.results.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "operation": args.operation, "parameter": args.parameter,
              "firmware": str(firmware), "firmware_sha256": hashlib.sha256(firmware.read_bytes()).hexdigest(),
              "vectors": str(vectors), "vectors_sha256": hashlib.sha256(vectors.read_bytes()).hexdigest(),
              "commands": str(ROOT / "UARTHELPER" / f"SCLOUD{args.operation.upper()}" /
                              f"{args.operation}_commands_{args.parameter}.txt"),
              "commands_sha256": hashlib.sha256((ROOT / "UARTHELPER" /
                              f"SCLOUD{args.operation.upper()}" /
                              f"{args.operation}_commands_{args.parameter}.txt").read_bytes()).hexdigest(),
              "port": args.port, "results": []}
    report_path = args.results / "results.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        import serial
        with serial.Serial(args.port, 115200, timeout=120, write_timeout=120,
                           exclusive=True) as device, (args.results / "transcript.txt").open(
                               "w", encoding="ascii") as log:
            upload(args.openocd, firmware, log)
            time.sleep(1)
            startup = device.read(device.in_waiting).decode("ascii")
            log.write(startup)
            log.flush()
            if f"READY SCLOUD_{args.operation.upper()}" not in startup or \
                    f"PARA={args.parameter}" not in startup:
                raise ValueError(f"wrong startup banner: {startup!r}")
            port = LoggedPort(device, log)
            for case, command in cases:
                record = {"count": case.count, "kind": getattr(case, "kind", "valid")}
                report["results"].append(record)
                try:
                    record.update(verify(args.operation, args.parameter, case, command, port))
                    print(f"PASS Scloud+{args.parameter} {args.operation} "
                          f"Count={case.count} {record['kind']}: "
                          f"{record['cycles']['CYCLES_ALGORITHM_TOTAL']} cycles", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    raise
                finally:
                    report_path.write_text(json.dumps(report, indent=2) + "\n")
        report.update(status="PASS", completed_at=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=("keygen", "encaps", "decaps"), required=True)
    parser.add_argument("--parameter", type=int, choices=(128, 192, 256, 512), required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--openocd", type=Path, default=OPENOCD)
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
