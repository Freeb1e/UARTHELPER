#!/usr/bin/env python3
"""Load an optimized HWDISPLAY ML-KEM image and record board comparisons."""

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
FIELDS = {"CYCLES_ALGORITHM_TOTAL", "POLY_OPERATIONS", "POLY_HW_CYCLES",
          "SAMPLER_CALLS", "SAMPLER_HW_CYCLES", "HASH_JOBS"}


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
    directory = ROOT / "UARTHELPER" / f"MLKEM{operation.upper()}"
    sys.path.insert(0, str(directory))
    helper = importlib.import_module(f"run_{operation}_tests")
    name = {"keygen": "keygen_commands", "encaps": "encaps_inputs",
            "decaps": "decaps_inputs"}[operation]
    inputs = directory / f"{name}_{parameter}.txt"
    loader = helper.load_coins if operation == "keygen" else helper.load_inputs
    vectors = helper.build_golden(parameter, loader(inputs, parameter))
    return inputs, helper, vectors


def command_for(operation, parameter, vector):
    if operation == "keygen":
        parts = (vector.coins,)
    elif operation == "encaps":
        parts = (vector.public_key, vector.encaps_coins)
    else:
        parts = (vector.secret_key, vector.ciphertext)
    return (f"{operation.upper()} {parameter} " +
            " ".join(part.hex().upper() for part in parts) + "\n").encode("ascii")


def parse_metrics(metrics):
    if set(metrics) != FIELDS:
        raise ValueError(f"unexpected metric fields: {metrics}")
    parsed = {}
    for name, value in metrics.items():
        if name.endswith("HW_CYCLES"):
            high, low = (int(part) for part in value.split(":"))
            if high < 0 or not 0 <= low < 2**32:
                raise ValueError(f"invalid {name}: {value}")
            parsed[name] = (high << 32) | low
        else:
            parsed[name] = int(value)
        if parsed[name] < 0:
            raise ValueError(f"negative {name}")
    if parsed["CYCLES_ALGORITHM_TOTAL"] == 0 or parsed["POLY_OPERATIONS"] == 0 or \
            parsed["HASH_JOBS"] == 0:
        raise ValueError("missing hardware activity or zero algorithm cycles")
    return parsed


def check_vector(operation, parameter, helper, vector, port):
    command = command_for(operation, parameter, vector)
    if port.write(command) != len(command):
        raise ValueError("short UART write")
    port.flush()
    received = helper.receive_result(port, parameter, 120)
    if operation == "keygen":
        expected = {"PK": vector.public_key, "SK": vector.secret_key}
        actual = {"PK": received[0], "SK": received[1]}
    elif operation == "encaps":
        expected = {"CT": vector.ciphertext, "SS": vector.shared_secret}
        actual = {"CT": received[0], "SS": received[1]}
    else:
        expected = {"SS": vector.shared_secret}
        actual = {"SS": received[0]}
    for field in expected:
        if actual[field] != expected[field]:
            raise ValueError(f"{field} mismatch")
    return {"kind": getattr(vector, "kind", "valid"), "status": "PASS",
            "command_sha256": hashlib.sha256(command).hexdigest(),
            "output_sha256": {field: hashlib.sha256(value).hexdigest()
                              for field, value in actual.items()},
            "checked_fields": list(actual), "metrics": parse_metrics(received[-1])}


def upload(firmware, log, openocd):
    command = [str(openocd), "-f", str(CONFIG), "-c", "reset halt",
               "-c", f"load_image {firmware}", "-c", f"verify_image {firmware}",
               "-c", "resume 0x80000000", "-c", "shutdown"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    log.write(output)
    log.flush()
    if result.returncode != 0 or "verified" not in output:
        raise ValueError(f"JTAG load/verify failed: {output}")


def run(args):
    inputs, helper, vectors = prepare(args.operation, args.parameter)
    firmware = (ROOT / "e203_hbirdv2/scripts/HWDISPLAY" /
                f"kd_mlkem_{args.operation}" /
                f"kd_mlkem_{args.operation}.elf")
    args.results.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "operation": args.operation, "parameter": args.parameter,
              "build_flags": "-O3 -DKD_POLY_ACCEL -DKD_SAMPLER_ACCEL "
                             "-DKD_HASH_SAMPLER_DIRECT -DKD_ACCEL_STRICT",
              "firmware": str(firmware),
              "firmware_sha256": hashlib.sha256(firmware.read_bytes()).hexdigest(),
              "inputs": str(inputs), "inputs_sha256": hashlib.sha256(inputs.read_bytes()).hexdigest(),
              "reference": "project Kyber ref, host-built deterministic golden",
              "port": args.port, "results": []}
    result_path = args.results / "results.json"
    result_path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        import serial
        with serial.Serial(args.port, 115200, timeout=2, write_timeout=120,
                           exclusive=True) as device, (args.results / "transcript.txt").open(
                               "w", encoding="ascii") as log:
            upload(firmware, log, args.openocd)
            port = LoggedPort(device, log)
            deadline = time.monotonic() + 10
            banner = f"READY MLKEM_{args.operation.upper()} PARA=512,768,1024 "
            while time.monotonic() < deadline:
                if port.readline().decode("ascii", errors="replace").startswith(banner):
                    break
            else:
                raise ValueError(f"missing startup banner: {banner}")
            for index, vector in enumerate(vectors, 1):
                record = {"index": index, "kind": getattr(vector, "kind", "valid")}
                report["results"].append(record)
                try:
                    record.update(check_vector(args.operation, args.parameter, helper, vector, port))
                    print(f"PASS {args.operation} {args.parameter} #{index} {record['kind']} "
                          f"{record['metrics']['CYCLES_ALGORITHM_TOTAL']} cycles", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    raise
                finally:
                    result_path.write_text(json.dumps(report, indent=2) + "\n")
        report.update(status="PASS", completed_at=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        result_path.write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", required=True, choices=("keygen", "encaps", "decaps"))
    parser.add_argument("--parameter", required=True, type=int, choices=(512, 768, 1024))
    parser.add_argument("--port", default="/dev/ttyUSB2")
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--openocd", type=Path, default=OPENOCD)
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
