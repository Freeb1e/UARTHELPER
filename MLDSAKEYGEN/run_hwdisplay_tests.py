#!/usr/bin/env python3
"""Verify and record HWDISPLAY ML-DSA firmware on the physical board."""

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
OPENOCD = Path("/home/tomoyo/NucleiStudio_IDE_202510-lin64/"
               "NucleiStudio_IDE_202510/NucleiStudio/toolchain/openocd/bin/openocd")
CONFIG = ROOT / "e203_hbirdv2/scripts/HWDISPLAY/scloud_encaps/openocd_ilm.cfg"
COUNTERS = {"CYCLES_ALGORITHM_TOTAL", "POLY_OPERATIONS", "POLY_HW_CYCLES",
            "SAMPLER_CALLS", "SAMPLER_HW_CYCLES", "HASH_JOBS"}
SIGN_COUNTERS = {"SIGN_ATTEMPTS", "SIGN_ATTEMPT_CYCLES", "SIGN_SUCCESS_CYCLES",
                 "SIGN_REJECT_Z", "SIGN_REJECT_Z_CYCLES", "SIGN_REJECT_W0",
                 "SIGN_REJECT_W0_CYCLES", "SIGN_REJECT_H", "SIGN_REJECT_H_CYCLES",
                 "SIGN_REJECT_OMEGA", "SIGN_REJECT_OMEGA_CYCLES"}


class LoggedPort:
    def __init__(self, device, log):
        self.device = device
        self.log = log

    def write(self, data):
        self.log.write("TX " + data.decode("ascii"))
        self.log.flush()
        return self.device.write(data)

    def flush(self):
        self.device.flush()

    def readline(self):
        data = self.device.readline()
        if data:
            self.log.write("RX " + data.decode("ascii", errors="replace").rstrip("\r\n") + "\n")
            self.log.flush()
        return data


def prepare(operation, parameter):
    directory = ROOT / "UARTHELPER" / f"MLDSA{operation.upper()}"
    sys.path.insert(0, str(directory))
    helper = importlib.import_module(f"run_{operation}_tests")
    inputs = directory / f"{operation}_commands_{parameter}.txt"
    loader = helper.load_seeds if operation == "keygen" else helper.load_inputs
    return inputs, helper, helper.build_golden(parameter, loader(inputs, parameter))


def command_for(operation, parameter, vector):
    if operation == "keygen":
        parts = (vector.seed,)
    elif operation == "sign":
        parts = (vector.secret_key, vector.source.message, vector.source.sign_random)
    else:
        parts = (vector.public_key, vector.message, vector.signature)
    return (f"{operation.upper()} {parameter} " +
            " ".join(part.hex().upper() for part in parts) + "\n").encode("ascii")


def parse_metrics(operation, metrics, helper=None):
    expected = COUNTERS | (SIGN_COUNTERS | {"IMPLEMENTATION"} if operation == "sign" else set())
    if set(metrics) != expected:
        raise ValueError(f"unexpected metrics: {metrics}")
    if operation == "sign" and metrics["IMPLEMENTATION"] != "hardware":
        raise ValueError(f"wrong Sign implementation: {metrics['IMPLEMENTATION']}")
    parsed = {}
    for name, value in metrics.items():
        if name == "IMPLEMENTATION":
            continue
        if name.endswith("HW_CYCLES"):
            high, low = (int(part) for part in value.split(":"))
            if high < 0 or not 0 <= low < 2**32:
                raise ValueError(f"invalid {name}: {value}")
            parsed[name] = (high << 32) | low
        else:
            parsed[name] = int(value)
        if parsed[name] < 0:
            raise ValueError(f"negative {name}")
    if any(parsed[name] == 0 for name in ("CYCLES_ALGORITHM_TOTAL", "POLY_OPERATIONS",
                                           "SAMPLER_CALLS", "HASH_JOBS")):
        raise ValueError("missing algorithm cycles or hardware activity")
    if operation == "sign":
        helper.parse_measurement(metrics)
    return parsed


def verify(operation, parameter, helper, vector, port):
    command = command_for(operation, parameter, vector)
    if port.write(command) != len(command):
        raise ValueError("short UART write")
    port.flush()
    response = helper.receive_result(port, parameter, 300)
    if operation == "keygen":
        expected = {"PK": vector.public_key, "SK": vector.secret_key}
        actual = {"PK": response[0], "SK": response[1]}
    elif operation == "sign":
        expected = {"SIG": vector.signature}
        actual = {"SIG": response[0]}
    else:
        expected = {"VALID": vector.expected_valid}
        actual = {"VALID": response[0]}
    for name, value in expected.items():
        if actual[name] != value:
            raise ValueError(f"{name} mismatch for {getattr(vector, 'label', 'input')}")
    return {"status": "PASS", "label": getattr(vector, "label", "valid"),
            "command_sha256": hashlib.sha256(command).hexdigest(),
            "checked_fields": list(actual),
            "output_sha256": {name: hashlib.sha256(value).hexdigest()
                              for name, value in actual.items() if isinstance(value, bytes)},
            "valid": actual.get("VALID"),
            "metrics": parse_metrics(operation, response[-1], helper)}


def upload(firmware, openocd, log):
    command = [str(openocd), "-f", str(CONFIG), "-c", "reset halt",
               "-c", f"load_image {firmware}", "-c", f"verify_image {firmware}",
               "-c", "resume 0x80000000", "-c", "shutdown"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    log.write(output)
    log.flush()
    if result.returncode or "verified" not in output:
        raise ValueError(f"JTAG load/verify failed: {output}")


def run(args):
    inputs, helper, vectors = prepare(args.operation, args.parameter)
    firmware = (ROOT / "e203_hbirdv2/scripts/HWDISPLAY" /
                f"kd_mldsa_{args.operation}" /
                f"kd_mldsa_{args.operation}_{args.parameter}.elf")
    firmware_hash = hashlib.sha256(firmware.read_bytes()).hexdigest()
    args.results.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "operation": args.operation, "parameter": args.parameter,
              "firmware": str(firmware), "firmware_sha256": firmware_hash,
              "inputs": str(inputs), "inputs_sha256": hashlib.sha256(inputs.read_bytes()).hexdigest(),
              "reference": "project Dilithium ref, host-built deterministic golden",
              "port": args.port, "results": []}
    path = args.results / "results.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        import serial
        with serial.Serial(args.port, 115200, timeout=2, write_timeout=120,
                           exclusive=True) as device, (args.results / "transcript.txt").open(
                               "w", encoding="ascii") as log:
            upload(firmware, args.openocd, log)
            port = LoggedPort(device, log)
            deadline = time.monotonic() + 12
            banner = f"READY MLDSA_{args.operation.upper()} PARA={args.parameter} "
            while time.monotonic() < deadline:
                if port.readline().decode("ascii", errors="replace").startswith(banner):
                    break
            else:
                raise ValueError(f"missing startup banner: {banner}")
            for index, vector in enumerate(vectors, 1):
                record = {"index": index, "label": getattr(vector, "label", "valid")}
                report["results"].append(record)
                try:
                    record.update(verify(args.operation, args.parameter, helper, vector, port))
                    metrics = record["metrics"]
                    print(f"PASS {args.operation} {args.parameter} #{index} {record['label']} "
                          f"{metrics['CYCLES_ALGORITHM_TOTAL']} cycles"
                          + (f" attempts={metrics['SIGN_ATTEMPTS']}" if args.operation == "sign" else ""),
                          flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    raise
                finally:
                    path.write_text(json.dumps(report, indent=2) + "\n")
        report.update(status="PASS", completed_at=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        path.write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", required=True, choices=("keygen", "sign", "verify"))
    parser.add_argument("--parameter", required=True, type=int, choices=(44, 65, 87))
    parser.add_argument("--port", default="/dev/ttyUSB2")
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--openocd", default=OPENOCD, type=Path)
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
