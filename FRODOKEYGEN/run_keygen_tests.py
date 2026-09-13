#!/usr/bin/env python3
"""Independent Frodo keygen test entry point."""

from pathlib import Path
import sys

DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(DIRECTORY.parent / "FRODO"))
from stage_runner import main

if __name__ == "__main__":
    sys.exit(main("keygen", DIRECTORY))
