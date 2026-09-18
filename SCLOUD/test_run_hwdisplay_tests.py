from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_hwdisplay_tests as board


class BoardRunnerTests(unittest.TestCase):
    def test_firmware_paths(self):
        for parameter in (128, 192, 256, 512):
            for operation in ("keygen", "encaps", "decaps"):
                with self.subTest(parameter=parameter, operation=operation):
                    path = board.firmware_path(operation, parameter)
                    app = f"scloud{'512' if parameter == 512 else ''}_{operation}"
                    self.assertEqual(path.parent.name, app)
                    self.assertEqual(path.name, f"{app}{'' if parameter == 512 else '_' + str(parameter)}.elf")
                    self.assertEqual(path.parent.parent.name, "HWDISPLAY")

    def test_decaps_selects_valid_and_tampered_count_zero(self):
        command = (board.ROOT / "UARTHELPER/SCLOUDDECAPS/decaps_commands_128.txt"
                   ).read_text(encoding="ascii").splitlines()[0]
        _, _, sk, ct = command.split()
        cases = [SimpleNamespace(count=i, kind="valid", sk=bytes.fromhex(sk),
                                 ct=bytes.fromhex(ct)) for i in range(10)]
        cases.append(SimpleNamespace(count=0, kind="tampered"))
        with patch.object(board.decaps, "load_cases", return_value=(128, cases)), \
             patch.object(board.decaps, "build_commands", return_value=[b"tampered\n"]) as build:
            _, selected = board.prepare("decaps", 128)
        self.assertEqual([case.kind for case, _ in selected], ["valid", "tampered"])
        self.assertEqual(selected[0][1], (command + "\n").encode("ascii"))
        build.assert_called_once_with(128, [cases[-1]])

    def test_prepared_first_commands_match_previous_board_transcripts(self):
        for operation in ("keygen", "encaps", "decaps"):
            for parameter in (128, 192, 256, 512):
                with self.subTest(operation=operation, parameter=parameter):
                    _, cases = board.prepare(operation, parameter)
                    transcript = (board.ROOT / "evidence/hwdisplay_scloud_20260918" /
                                  f"{operation}_{parameter}/transcript.txt")
                    if transcript.exists():
                        sent = next(line[3:] for line in transcript.read_text(
                            encoding="ascii").splitlines() if line.startswith("TX "))
                        self.assertEqual(cases[0][1].decode("ascii").strip().lower(),
                                         sent.lower())

    def test_full_output_and_stage_validation(self):
        case = SimpleNamespace(count=0, public_key=b"PK", secret_key=b"SK")
        cycles = {f"CYCLES_{name}": 1 for name in board.LOW_STAGES["keygen"]}
        cycles["CYCLES_ALGORITHM_TOTAL"] = len(cycles) + 1

        class Port:
            fields = {}

            def write(self, command):
                return len(command)

            def flush(self):
                pass

        port = Port()
        with patch.object(board.keygen, "receive_result", return_value=(b"PK", b"SK", cycles)):
            result = board.verify("keygen", 128, case, b"command\n", port)
        self.assertEqual(result["checked_fields"], ["PK", "SK"])
        self.assertEqual(result["cycles"], cycles)
        with patch.object(board.keygen, "receive_result", return_value=(b"PK", b"bad", cycles)):
            with self.assertRaisesRegex(ValueError, "SK mismatch"):
                board.verify("keygen", 128, case, b"command\n", port)
        incomplete = dict(cycles)
        del incomplete["CYCLES_HASH_PK"]
        with patch.object(board.keygen, "receive_result", return_value=(b"PK", b"SK", incomplete)):
            with self.assertRaisesRegex(ValueError, "unexpected cycle fields"):
                board.verify("keygen", 128, case, b"command\n", port)


if __name__ == "__main__":
    unittest.main()
