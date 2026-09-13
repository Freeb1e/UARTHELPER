import json
from itertools import product
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stage_runner


class StageRunnerTests(unittest.TestCase):
    def test_single_line_selection_for_each_independent_stage(self):
        for operation, compact in product(("keygen", "encaps", "decaps"), (False, True)):
            with self.subTest(operation=operation, compact=compact), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                expected = {"keygen": {"PK": "AB", "PKH": "CD"},
                            "encaps": {"CT": "AB", "SS": "CD"},
                            "decaps": {"SS": "CD", "FAIL_MASK": "0"}}[operation]
                requests = [dict(case=case, operation=operation, expected=expected,
                                 command=f"{operation.upper()} 640 1 1 {case}")
                            for case in (10, 20)]
                with patch.object(stage_runner, "read_stage_files", return_value=requests), \
                     patch.object(stage_runner, "execute") as execute:
                    status = stage_runner.main(operation, directory, [
                        "--parameter", "640", "--port", "mock",
                        "--results", str(directory / "results"), "--line", "2"] +
                        (["--compact"] if compact else []))
                    self.assertEqual(status, 0)
                    selected = execute.call_args.args[1]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(selected[0]["case"], 20)
                    self.assertEqual(selected[0]["command"].split()[3],
                                     "0" if compact and operation != "decaps" else "1")
                    fields = ({"keygen": ["PKH"], "encaps": ["SS"],
                               "decaps": ["SS", "FAIL_MASK"]}[operation]
                              if compact else list(expected))
                    self.assertEqual(selected[0]["verified_fields"], fields)
                    summary = json.loads((directory / "results/summary.json").read_text())
                    self.assertEqual(summary["verification_mode"], "compact" if compact else "full")

    def test_invalid_line_never_opens_board(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(stage_runner, "read_stage_files", return_value=[{}]), \
                 patch.object(stage_runner, "execute") as execute:
                status = stage_runner.main("decaps", directory, [
                    "--parameter", "640", "--port", "mock",
                    "--results", str(directory / "results"), "--line", "0"])
                self.assertEqual(status, 1)
                execute.assert_not_called()
                self.assertFalse((directory / "results").exists())

    def test_existing_results_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = directory / "results"
            result.mkdir()
            sentinel = result / "summary.json"
            sentinel.write_text("previous evidence")
            with patch.object(stage_runner, "read_stage_files", return_value=[{}]), \
                 patch.object(stage_runner, "execute") as execute:
                self.assertEqual(stage_runner.main("keygen", directory, [
                    "--parameter", "640", "--port", "mock",
                    "--results", str(result)]), 1)
                execute.assert_not_called()
                self.assertEqual(sentinel.read_text(), "previous evidence")


if __name__ == "__main__":
    unittest.main()
