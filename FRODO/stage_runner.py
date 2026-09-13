"""Shared CLI for the three independent Frodo UART test directories."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

from run_board_tests import DEFAULT_OPENOCD, PARAMETERS, save_json
from run_kat_tests import digest, execute, read_stage_files


def main(operation, directory, argv=None):
    parser = argparse.ArgumentParser(
        description=f"Load Frodo {operation} firmware and compare complete reference outputs.")
    parser.add_argument("--parameter", type=int, choices=PARAMETERS, required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--openocd", type=Path, default=DEFAULT_OPENOCD)
    parser.add_argument("--line", type=int, help="run only this 1-based command/reference line")
    args = parser.parse_args(argv)
    summary = dict(status="RUNNING", operation=operation, parameter=args.parameter,
                   started_at=datetime.now(timezone.utc).isoformat(),
                   port=args.port, baud_rate=115200, passed=0)
    created = False
    try:
        requests = read_stage_files(directory, args.parameter, operation)
        if args.line is not None:
            if not 1 <= args.line <= len(requests):
                raise ValueError(f"--line must be between 1 and {len(requests)}")
            requests = [requests[args.line - 1]]
        args.results.mkdir(parents=True, exist_ok=False)
        created = True
        summary.update(total=len(requests), command_line=args.line,
                       source_sha256={str(path): digest(path) for path in
                                      directory.glob(f"*_{args.parameter}.*")})
        save_json(args.results / "summary.json", summary)
        execute(args, requests, summary)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        if created:
            summary.update(status="FAIL", error=str(error))
            save_json(args.results / "summary.json", summary)
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0
