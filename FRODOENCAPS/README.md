# Frodo Encaps UART tests

`run_encaps_tests.py` reads the non-empty, non-comment lines in
`encaps_commands.txt`. It validates each command before opening the serial
port, sends one command over a 115200 8N1 link, waits for that response's
`END`, extracts `SS`, and only then sends the next command. A board `ERROR`
response or timeout stops the test immediately.

After all commands complete, the script writes one uppercase shared secret per
line to `ss_board.txt` and compares that file byte for byte with the provided
`ss.txt` reference. A mismatch prints a diff and exits with status 1.

The commands below assume the current directory is `~/project`, which contains
both `e203_hbirdv2` and `UARTHELPER`. Install the serial dependency with:

```sh
python3 -m pip install -r UARTHELPER/FRODOENCAPS/requirements.txt
```

Run the tests against the board (replace the port if needed):

```sh
python3 UARTHELPER/FRODOENCAPS/run_encaps_tests.py --port /dev/ttyUSB0
```

When the current directory is `~/project/e203_hbirdv2`, use:

```sh
python3 -m pip install -r ../UARTHELPER/FRODOENCAPS/requirements.txt
python3 ../UARTHELPER/FRODOENCAPS/run_encaps_tests.py --port /dev/ttyUSB0
```

Useful options are `--baud-rate`, `--timeout`, `--startup-delay`, `--commands`,
`--reference`, and `--output`. Paths for the three files default to the
`FRODOENCAPS` directory, so the command may be run from any working directory.

Run the protocol tests without a board:

```sh
python3 -m unittest discover -s UARTHELPER/FRODOENCAPS -p 'test_*.py'
```
