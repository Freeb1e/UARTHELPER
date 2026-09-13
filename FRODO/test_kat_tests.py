import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from run_kat_tests import (
    export_stage_files, read_stage_files, read_kat, verified_prior_results,
)
from run_board_tests import SIZES


class ExistingVectorTests(unittest.TestCase):
    def test_prior_results_require_same_input_firmware_and_complete_output(self):
        request = dict(parameter=640, operation="decaps", source="official.rsp",
                       case=0, kind="valid", command="DECAPS fixture",
                       expected={"SS": "AB", "FAIL_MASK": "0"})
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
                        (directory / f"cases_{parameter}.jsonl").write_text("")
                        with self.assertRaises(ValueError):
                            read_stage_files(directory, parameter, operation)

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
