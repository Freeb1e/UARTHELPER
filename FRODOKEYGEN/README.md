# Frodo KeyGen UART tests

`run_keygen_tests.py` reads the non-empty, non-comment lines in
`keygen_commands.txt`. It sends one command over a 115200 8N1 serial link,
waits for that response's `END`, extracts `PKH`, and only then sends the next
command. A board `ERROR` response or timeout stops the test immediately.

After all commands complete, the script writes one uppercase PKH per line to
`pkh.txt` and compares that file byte for byte with `pkh_ref.txt`. A mismatch
prints a diff and exits with status 1.

The commands below assume the current directory is `~/project`, which contains
both `e203_hbirdv2` and `UARTHELPER`. Install the serial dependency with:

```sh
cd ~/project
python3 -m pip install -r UARTHELPER/FRODOKEYGEN/requirements.txt
```

Run against the board (replace the port if needed):

```sh
python3 UARTHELPER/FRODOKEYGEN/run_keygen_tests.py --port /dev/ttyUSB0
```

When the current directory is `~/project/e203_hbirdv2`, use the sibling path
instead:

```sh
python3 -m pip install -r ../UARTHELPER/FRODOKEYGEN/requirements.txt
python3 ../UARTHELPER/FRODOKEYGEN/run_keygen_tests.py --port /dev/ttyUSB0
```

Use `python3 -m pip`, not `pip3.13`, if the standalone `pip3.13` launcher has
an invalid interpreter path. Upgrading pip is not required for this tool.

Useful options are `--baud-rate`, `--timeout`, `--startup-delay`, `--commands`,
`--reference`, and `--output`. Paths for the three files default to this
directory, so the command may be run from any working directory.

Run the protocol tests without a board:

```sh
python3 -m unittest discover -s UARTHELPER/FRODOKEYGEN -p 'test_*.py'
```
