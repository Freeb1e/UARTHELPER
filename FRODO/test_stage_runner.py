from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stage_runner


class StageRunnerTests(unittest.TestCase):
    def test_single_line_selection_for_each_independent_stage(self):
        for operation in ("keygen", "encaps", "decaps"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                requests = [{"case": 10}, {"case": 20}]
                with patch.object(stage_runner, "read_stage_files", return_value=requests), \
                     patch.object(stage_runner, "execute") as execute:
                    status = stage_runner.main(operation, directory, [
                        "--parameter", "640", "--port", "mock",
                        "--results", str(directory / "results"), "--line", "2"])
                    self.assertEqual(status, 0)
                    self.assertEqual(execute.call_args.args[1], [requests[1]])

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
