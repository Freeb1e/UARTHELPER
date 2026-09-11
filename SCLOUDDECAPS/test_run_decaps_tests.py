import io
from pathlib import Path
import unittest
from contextlib import redirect_stdout

import run_decaps_tests as runner


class Port:
    def __init__(self, lines):
        self.lines = list(lines)
        self.writes = []

    def readline(self):
        return self.lines.pop(0) if self.lines else b""

    def write(self, data):
        self.writes.append(data)
        return len(data)

    def flush(self):
        pass


def response(mask=0):
    return [b"OK PARA=128 FAMILY=SM3\n", b"SS=aabb\n",
            f"FAIL_MASK={mask}\n".encode(), b"CPU_HZ=20000000\n",
            b"CYCLES_ALGORITHM_TOTAL=100\n", b"END\n"]


class DecapsTests(unittest.TestCase):
    def test_all_kats_and_tampered_command(self):
        root = Path(__file__).resolve().parents[2]
        for p in (128, 192, 256, 512):
            parameter, cases = runner.load_cases(root / f"third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-{p}-SM3-packed10.txt")
            self.assertEqual(parameter, p)
            self.assertEqual(len(cases), 11)
            self.assertEqual([c.fail_mask for c in cases], [0] * 10 + [255])
            self.assertEqual(cases[-1].ct[:-1], cases[0].ct[:-1])
            self.assertEqual(cases[-1].ct[-1] ^ cases[0].ct[-1], 0x80)
            self.assertNotEqual(cases[-1].ss, cases[0].ss)
            for case, command in zip(cases, runner.build_commands(p, cases)):
                fields = command.decode().split()
                self.assertEqual(fields[:2], ["DECAPS", str(p)])
                self.assertEqual(bytes.fromhex(fields[2]), case.sk)
                self.assertEqual(bytes.fromhex(fields[3]), case.ct)
                self.assertEqual(len(case.ss), p // 8)

    def test_valid_and_rejected_result(self):
        for mask in (0, 255):
            ss, actual, cycles, hz = runner.receive_result(Port(response(mask)), 128, 1)
            self.assertEqual((ss, actual, hz), (b"\xaa\xbb", mask, 20000000))
            self.assertEqual(cycles["CYCLES_ALGORITHM_TOTAL"], 100)

    def test_incomplete_wrong_parameter_duplicate_and_invalid_mask(self):
        for lines in ([b"END\n"], response()[1:], response(1),
                      [b"OK PARA=192 FAMILY=SM3\n"] + response()[1:],
                      response()[:-1] + [b"SS=aabb\n", b"END\n"]):
            with self.subTest(lines=lines), self.assertRaises(runner.KeygenTestError):
                runner.receive_result(Port(lines), 128, 1)

    def test_board_error_and_timeout(self):
        for lines in ([b"ERROR COMMAND\n"], []):
            with self.assertRaises(runner.KeygenTestError):
                runner.receive_result(Port(lines), 128, 0.001)

    def test_wrong_shared_secret_stops(self):
        case = runner.Case(0, "valid", b"", b"", b"wrong", 0)
        port = Port(response())
        with redirect_stdout(io.StringIO()), self.assertRaises(runner.KeygenTestError):
            runner.run_cases(port, 128, [case, case], [b"first\n", b"second\n"], 1)
        self.assertEqual(port.writes, [b"first\n"])

    def test_wrong_fail_mask_stops_even_when_secret_matches(self):
        case = runner.Case(0, "tampered", b"", b"", b"\xaa\xbb", 255)
        with redirect_stdout(io.StringIO()), self.assertRaises(runner.KeygenTestError):
            runner.run_cases(Port(response()), 128, [case], [b"test\n"], 1)


if __name__ == "__main__":
    unittest.main()
