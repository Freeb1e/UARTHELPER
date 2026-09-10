import io
import unittest
from contextlib import redirect_stdout

import run_encaps_tests as runner


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


def response(ct="aabb"):
    return [b"OK PARA=128 FAMILY=SM3\n", f"CT={ct}\n".encode(), b"SS=cc\n",
            b"CPU_HZ=20000000\n", b"CYCLES_ALGORITHM_TOTAL=100\n", b"END\n"]


class EncapsTests(unittest.TestCase):
    def test_supported_kats_and_generated_commands(self):
        for parameter in (128, 192, 256):
            path = runner.PROJECT_ROOT / f"third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-{parameter}-SM3-packed10.txt"
            actual, vectors = runner.load_kats(path)
            self.assertEqual(actual, parameter)
            self.assertEqual(len(vectors), 10)
            commands = runner.build_commands(parameter, vectors)
            self.assertEqual(len(commands), 10)
            for vector, command in zip(vectors, commands):
                fields = command.decode().split()
                self.assertEqual(fields[:2], ["ENCAPS", str(parameter)])
                self.assertEqual(bytes.fromhex(fields[2]), vector.pk)
                self.assertEqual(len(bytes.fromhex(fields[3])), parameter // 8)

    def test_receive_complete_result(self):
        ct, ss, cycles, hz = runner.receive_result(Port(response()), 128, 1)
        self.assertEqual((ct, ss), (b"\xaa\xbb", b"\xcc"))
        self.assertEqual((cycles["CYCLES_ALGORITHM_TOTAL"], hz), (100, 20000000))

    def test_receive_rejects_incomplete_wrong_parameter_and_duplicate(self):
        for lines in ([b"END\n"], response()[1:],
                      [b"OK PARA=192 FAMILY=SM3\n"] + response()[1:],
                      response()[:-1] + [b"CT=aabb\n", b"END\n"]):
            with self.subTest(lines=lines), self.assertRaises(runner.KeygenTestError):
                runner.receive_result(Port(lines), 128, 1)

    def test_receive_rejects_error_and_malformed_hex(self):
        for lines in ([b"ERROR COMMAND\n"], response("xyz")):
            with self.assertRaises(runner.KeygenTestError):
                runner.receive_result(Port(lines), 128, 1)

    def test_ct_mismatch_stops_before_next_command(self):
        vector = runner.Vector(0, bytes(64), bytes(1), b"wrong", b"\xcc")
        port = Port(response())
        with redirect_stdout(io.StringIO()), self.assertRaises(runner.KeygenTestError):
            runner.run_vectors(port, 128, [vector, vector], [b"first\n", b"second\n"], 1)
        self.assertEqual(port.writes, [b"first\n"])

    def test_timeout(self):
        with self.assertRaisesRegex(runner.KeygenTestError, "timed out"):
            runner.receive_result(Port([]), 128, 0.001)


if __name__ == "__main__":
    unittest.main()
