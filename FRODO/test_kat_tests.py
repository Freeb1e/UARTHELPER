import json
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from run_kat_tests import (
    export_stage_files, read_stage_files, read_kat, verified_prior_results,
    verification_requests, execute, main,
)
from run_board_tests import SIZES, compare_response


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
                    version = 2 if operation == "keygen" else 1
                    port = MagicMock()
                    port.__enter__.return_value = port
                    port.in_waiting = 5
                    port.read.side_effect = [f"READY FRODO_{operation.upper()} {version}\r\n".encode()] + [
                        response[i:i + 5] for i in range(0, len(response), 5)]
                    port.write.return_value = len(payload)
                    summary = dict(verification_mode="compact")
                    with patch("serial.Serial", return_value=port), \
                         patch("run_kat_tests.upload", return_value="firmware hash"), \
                         patch("run_kat_tests.time.sleep"):
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

    def test_prior_results_require_same_input_firmware_and_complete_output(self):
        request = dict(parameter=640, operation="decaps", source="official.rsp",
                       case=0, kind="valid", command="DECAPS fixture",
                       expected={"SS": "AB", "FAIL_MASK": "0"},
                       verification_mode="full", verified_fields=["SS", "FAIL_MASK"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "test.elf"
            firmware.write_bytes(b"test firmware")
            result = dict(request, status="PASS", response={
                "SS": "AB", "FAIL_MASK": "0", "CYCLES_ALGORITHM_TOTAL": "1"},
                firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
                command_sha256=hashlib.sha256(b"DECAPS fixture\n").hexdigest())
            prior = root / "prior.jsonl"
            with patch("run_kat_tests.firmware_path", return_value=firmware):
                prior.write_text(json.dumps(dict(result, source="history.json")) + "\n" +
                                 json.dumps(result) + "\n")
                accepted = verified_prior_results(prior, [request])
                self.assertEqual(len(accepted), 1)
                self.assertEqual(next(iter(accepted.values()))["reused_from"]["line"], 2)
                for changed in (
                    dict(result, command_sha256="wrong"),
                    dict(result, firmware_sha256="wrong"),
                    dict(result, response=dict(result["response"], SS="AC")),
                ):
                    prior.write_text(json.dumps(changed) + "\n")
                    with self.assertRaises(ValueError):
                        verified_prior_results(prior, [request])
                prior.write_text((json.dumps(result) + "\n") * 2)
                with self.assertRaises(ValueError):
                    verified_prior_results(prior, [request])

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

    def test_compact_reuse_cannot_count_as_full_keygen_or_encaps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "test.elf"
            firmware.write_bytes(b"test firmware")
            for operation, expected in (("keygen", {"PK": "AB", "PKH": "CD"}),
                                        ("encaps", {"CT": "AB", "SS": "CD"})):
                request = dict(parameter=640, operation=operation, source="official.rsp",
                               case=0, kind="valid", command=f"{operation.upper()} 640 1 1 AB",
                               expected=expected)
                compact = verification_requests([request], True)[0]
                record = dict(compact, status="PASS", response=dict(
                    compact["expected"], CYCLES_ALGORITHM_TOTAL="1"),
                    firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
                    command_sha256=hashlib.sha256((compact["command"] + "\n").encode()).hexdigest())
                prior = root / "prior.jsonl"
                prior.write_text(json.dumps(record) + "\n")
                with patch("run_kat_tests.firmware_path", return_value=firmware):
                    self.assertEqual(len(verified_prior_results(prior, [compact])), 1)
                    with self.assertRaisesRegex(ValueError, "command does not match"):
                        verified_prior_results(prior, verification_requests([request], False))

    def test_official_compact_cli_preserves_full_stage_files(self):
        request = dict(parameter=640, operation="keygen", source="official.rsp",
                       case=0, kind="valid", command="KEYGEN 640 1 1 " + "AB" * 64,
                       expected={"PK": "CD" * 9616, "PKH": "EF" * 16})
        for prepare_only in (False, True):
            with self.subTest(prepare_only=prepare_only), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                def read_batch(directory, parameter, operation):
                    if parameter == 640 and operation == "keygen":
                        return read_stage_files(directory, parameter, operation)
                    return []
                with patch("run_kat_tests.ROOT", root), \
                     patch("run_kat_tests.inventory", return_value=([request], {})), \
                     patch("run_kat_tests.read_stage_files", side_effect=read_batch), \
                     patch("run_kat_tests.execute") as execute:
                    status = main(["--reference-root", str(root), "--compact",
                                   "--results", str(root / "results")] +
                                  (["--prepare-only"] if prepare_only else []))
                self.assertEqual(status, 0)
                self.assertEqual(read_stage_files(root / "UARTHELPER/FRODOKEYGEN", 640, "keygen"),
                                 [request])
                summary = json.loads((root / "results/summary.json").read_text())
                self.assertEqual(summary["verification_mode"], "compact")
                if prepare_only:
                    execute.assert_not_called()
                    self.assertEqual(summary["status"], "PREPARED")
                else:
                    selected = execute.call_args.args[1][0]
                    self.assertEqual(selected["command"].split()[:4], ["KEYGEN", "640", "1", "0"])
                    self.assertEqual(selected["expected"], {"PKH": request["expected"]["PKH"]})

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
