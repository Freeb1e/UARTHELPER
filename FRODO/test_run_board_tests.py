import io
import unittest

from run_board_tests import build_requests, compare_response, firmware_path, receive, SIZES


class FragmentedPort:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    @property
    def in_waiting(self):
        return len(self.chunks[0]) if self.chunks else 0

    def read(self, count):
        return self.chunks.pop(0) if self.chunks else b""


class BoardProtocolTests(unittest.TestCase):
    def test_firmware_path_selects_parameter_specific_hwdisplay_image(self):
        self.assertEqual(firmware_path("keygen", 640).name, "frodo_keygen.elf")
        for operation in ("keygen", "encaps", "decaps"):
            path = firmware_path(operation, 976, "HWDISPLAY")
            self.assertEqual(path.name, f"frodo_{operation}_976.elf")
            self.assertEqual(path.parent.parent.name, "HWDISPLAY")

    def test_fragmented_large_field(self):
        value = "AB" * 21520
        response = ("OK PARA=1344\r\nPK=" + value + "\r\nEND\r\n").encode()
        chunks = [response[i:i + 17] for i in range(0, len(response), 17)]
        result = receive(FragmentedPort(chunks), 1344, 1, io.StringIO())
        self.assertEqual(result["PK"], value)

    def test_rejects_bad_acknowledgements_and_duplicate_fields(self):
        for response in (
            b"OK PARA=976\nEND\n",
            b"END\n",
            b"OK PARA=640\nOK PARA=640\nEND\n",
            b"OK PARA=640\nSS=00\nSS=00\nEND\n",
            b"ERROR HARDWARE 2\n",
            b"\xff\n",
        ):
            with self.subTest(response=response), self.assertRaises(ValueError):
                receive(FragmentedPort([response]), 640, 0.1, io.StringIO())

    def test_timeout_records_partial_response(self):
        log = io.StringIO()
        with self.assertRaises(TimeoutError):
            receive(FragmentedPort([b"OK PARA=640\nSS=AB"]), 640, 0.001, log)
        self.assertIn("PARTIAL_RX", log.getvalue())

    def test_checks_complete_output(self):
        expected = {"CT": "AABBCCDD"}
        for value in ("AABBCCDE", "AABBCC", "AABBCCGG", "AA BB CC"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compare_response({"CT": value, "CYCLES_ALGORITHM_TOTAL": "1"}, expected)

    def test_requires_correct_mask_and_cycles(self):
        for fields in (
            {"SS": "AB", "FAIL_MASK": "0", "CYCLES_ALGORITHM_TOTAL": "1"},
            {"SS": "AB", "FAIL_MASK": "255"},
            {"SS": "AB", "FAIL_MASK": "255", "CYCLES_ALGORITHM_TOTAL": "0"},
            {"SS": "AB", "FAIL_MASK": "255", "CYCLES_ALGORITHM_TOTAL": "x"},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                compare_response(fields, {"SS": "AB", "FAIL_MASK": "255"})
        self.assertEqual(compare_response(
            {"SS": "ab", "FAIL_MASK": "255", "CYCLES_ALGORITHM_TOTAL": "12"},
            {"SS": "AB", "FAIL_MASK": "255"}), {"CYCLES_ALGORITHM_TOTAL": 12})

    def test_all_parameters_and_stages(self):
        for parameter, sizes in SIZES.items():
            case = {name: "AB" * size for name, size in sizes.items()}
            case.update(index=0, rejected_ciphertext="CD" * sizes["ciphertext"],
                        rejected_shared_secret="EF" * sizes["shared_secret"])
            manifest = {"schema": "frodo-board-v1", "parameter": parameter, "cases": [case]}
            for operation, outputs in (("keygen", {"PK", "PKH"}),
                                       ("encaps", {"CT", "SS"}),
                                       ("decaps", {"SS", "FAIL_MASK"})):
                with self.subTest(parameter=parameter, operation=operation):
                    requests = build_requests(manifest, operation)
                    self.assertEqual(set(requests[0]["expected"]), outputs)
                    self.assertTrue(requests[0]["command"].startswith(
                        f"{operation.upper()} {parameter} 1 1 "))
                    self.assertEqual(len(requests), 2 if operation == "decaps" else 1)
                    if operation == "decaps":
                        self.assertEqual(requests[1]["expected"]["FAIL_MASK"], "255")
                        self.assertEqual(requests[1]["command"].split()[-1],
                                         case["rejected_ciphertext"])
            case["secret_key"] = "00"
            with self.assertRaises(ValueError):
                build_requests(manifest, "decaps")


if __name__ == "__main__":
    unittest.main()
