import json
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from run_kat_tests import (
    export_stage_files, read_stage_files, read_kat,
    verification_requests, execute, main,
)
from reference_vectors import SIZES, compare_response


class ExistingVectorTests(unittest.TestCase):
    def test_compact_uart_execution_records_actual_verification_scope(self):
        for parameter in SIZES:
            for operation, expected in (("keygen", {"PK": "AB", "PKH": "CD"}),
                                        ("encaps", {"CT": "AB", "SS": "CD"}),
                                        ("decaps", {"SS": "CD", "FAIL_MASK": "0"})):
                with self.subTest(parameter=parameter, operation=operation), \
                     tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    request = verification_requests([dict(
                        parameter=parameter, operation=operation, case=0, kind="valid",
                        source="official.rsp", command=f"{operation.upper()} {parameter} 1 1 AB",
                        expected=expected)], True)[0]
                    payload = (request["command"] + "\n").encode()
                    response = (f"OK PARA={parameter}\r\n" + "".join(
                        f"{name}={value}\r\n" for name, value in request["expected"].items()) +
                        "CPU_HZ=20000000\r\nCYCLES_ALGORITHM_TOTAL=123\r\nEND\r\n").encode()
                    port = MagicMock()
                    port.__enter__.return_value = port
                    port.in_waiting = 5
                    port.read.side_effect = [
                        response[i:i + 5] for i in range(0, len(response), 5)]
                    port.write.return_value = len(payload)
                    summary = dict(verification_mode="compact")
                    with patch("serial.Serial", return_value=port):
                        execute(SimpleNamespace(port="mock", results=root), [request], summary)
                    port.write.assert_called_once_with(payload)
                    record = json.loads((root / "results.jsonl").read_text())
                    self.assertEqual(record["status"], "PASS")
                    self.assertEqual(record["verification_mode"], "compact")
                    self.assertEqual(record["verified_fields"], list(request["expected"]))
                    self.assertNotIn("PK", record["response"])
                    self.assertNotIn("CT", record["response"])
                    self.assertEqual(record["command_sha256"], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(summary["status"], "PASS")
                    self.assertEqual(summary["passed"], 1)

    def test_stage_export_roundtrip_and_misaligned_reference(self):
        for parameter, sizes in SIZES.items():
            for operation in ("keygen", "encaps", "decaps"):
                inputs = {"keygen": ["keygen_randomness"],
                          "encaps": ["public_key", "encaps_randomness"],
                          "decaps": ["secret_key", "ciphertext"]}[operation]
                outputs = {"keygen": {"PK": "public_key", "PKH": "public_key_hash"},
                           "encaps": {"CT": "ciphertext", "SS": "shared_secret"},
                           "decaps": {"SS": "shared_secret"}}[operation]
                request = dict(parameter=parameter, operation=operation, case=0,
                               source="fixture", kind="valid",
                               command=f"{operation.upper()} {parameter} 1 1 " +
                               " ".join("AB" * sizes[name] for name in inputs),
                               expected={field: "CD" * sizes[name]
                                         for field, name in outputs.items()})
                if operation == "decaps":
                    request["expected"]["FAIL_MASK"] = "0"
                with self.subTest(parameter=parameter, operation=operation):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        export_stage_files([request], root)
                        directory = root / f"FRODO{operation.upper()}"
                        self.assertEqual(read_stage_files(directory, parameter, operation),
                                         [request])
                        original = {p.name: p.read_bytes() for p in directory.iterdir()}
                        compact = verification_requests(
                            read_stage_files(directory, parameter, operation), True)[0]
                        expected_fields = {"keygen": ["PKH"], "encaps": ["SS"],
                                           "decaps": ["SS", "FAIL_MASK"]}[operation]
                        self.assertEqual(list(compact["expected"]), expected_fields)
                        self.assertEqual(compact["verified_fields"], expected_fields)
                        self.assertEqual(compact["verification_mode"], "compact")
                        before, after = request["command"].split(), compact["command"].split()
                        self.assertEqual(after[:3], before[:3])
                        self.assertEqual(after[3], "1" if operation == "decaps" else "0")
                        self.assertEqual(after[4:], before[4:])
                        response = dict(compact["expected"], CYCLES_ALGORITHM_TOTAL="123")
                        self.assertEqual(compare_response(response, compact["expected"]),
                                         {"CYCLES_ALGORITHM_TOTAL": 123})
                        for field in expected_fields:
                            wrong = dict(response, **{field: "255" if field == "FAIL_MASK"
                                                      else "00" * (len(response[field]) // 2)})
                            with self.assertRaises(ValueError):
                                compare_response(wrong, compact["expected"])
                            missing = dict(response)
                            del missing[field]
                            with self.assertRaises(ValueError):
                                compare_response(missing, compact["expected"])
                        if operation != "decaps":
                            with self.assertRaises(ValueError):
                                compare_response(response, request["expected"])
                        self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, original)
                        full = verification_requests([request], False)[0]
                        self.assertEqual(full["command"], request["command"])
                        self.assertEqual(full["expected"], request["expected"])
                        (directory / f"cases_{parameter}.jsonl").write_text("")
                        with self.assertRaises(ValueError):
                            read_stage_files(directory, parameter, operation)

    def test_official_cli_preserves_full_stage_files(self):
        request = dict(parameter=640, operation="keygen", source="official.rsp",
                       case=0, kind="valid", command="KEYGEN 640 1 1 " + "AB" * 64,
                       expected={"PK": "CD" * 9616, "PKH": "EF" * 16})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def read_batch(directory, parameter, operation):
                if parameter == 640 and operation == "keygen":
                    return read_stage_files(directory, parameter, operation)
                return []
            with patch("run_kat_tests.ROOT", root), \
                 patch("run_kat_tests.inventory", return_value=([request], {})), \
                 patch("run_kat_tests.read_stage_files", side_effect=read_batch), \
                 patch("run_kat_tests.execute") as execute:
                status = main(["--reference-root", str(root),
                               "--results", str(root / "results")])
            self.assertEqual(status, 0)
            self.assertEqual(read_stage_files(root / "UARTHELPER/FRODOKEYGEN", 640, "keygen"),
                             [request])
            summary = json.loads((root / "results/summary.json").read_text())
            execute.assert_not_called()
            self.assertEqual(summary["status"], "PREPARED")

    def test_kat_rejects_missing_duplicate_and_nonsequential_fields(self):
        sizes = SIZES[640]
        fields = dict(count="0", seed="AB" * 48,
                      pk="AB" * sizes["public_key"], sk="AB" * sizes["secret_key"],
                      ct="AB" * sizes["ciphertext"], ss="AB" * sizes["shared_secret"])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "kat.rsp"
            content = "".join(f"{key} = {value}\n" for key, value in fields.items())
            path.write_text(content)
            self.assertEqual(read_kat(path, 640), [fields])
            for malformed in (content.replace("count = 0", "count = 1"),
                              content + "ss = 00\n",
                              content.rsplit("ss = ", 1)[0]):
                path.write_text(malformed)
                with self.assertRaises(ValueError):
                    read_kat(path, 640)


if __name__ == "__main__":
    unittest.main()
