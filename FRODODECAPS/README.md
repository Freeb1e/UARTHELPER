# Frodo decaps independent board tests

This directory contains only official KAT decaps inputs and references for
FrodoKEM-SHAKE-640/976/1344. Files use ASCII, LF line endings, uppercase hex
and no headers. Line N in every reference file corresponds exactly to line N
of the command file. Line N is official count N-1 (counts 0..99).
Historical and generated smoke cases are excluded. Keep the full command on one line.

| Parameter | Commands |
| --- | ---: |
| 640 | 100 |
| 976 | 100 |
| 1344 | 100 |

## Files

For each P in 640, 976, 1344:

- `decaps_commands_P.txt`: complete newline-terminated UART instructions.
- `ss_ref_P.txt` and `fail_mask_ref_P.txt`: one expected value per instruction.
- `cases_P.jsonl`: 1-based line number, source file, original case index and
  valid label (all official KAT ciphertexts are valid). Case index 0 is distinct from command line 1.

SS is the complete shared secret. FAIL_MASK is decimal 0 for every official KAT ciphertext. Both are checked.

## Independent Run

Run from the merged repository root; the board must have the accelerator
bitstream loaded and the matching ELF built:

```sh
.venv/bin/python -u UARTHELPER/FRODODECAPS/run_decaps_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --results /tmp/frodo-decaps-640
```

The script loads and verifies the CPU image through JTAG before sending this
stage's commands. Results must use a new directory. Override the installed
OpenOCD with `--openocd PATH`. The complete UART transcript and JSONL outcomes
are saved in that directory. Use `--line 1` to run just the first input and
its reference. Use the same option with another line number to reproduce any
individual case.

## Manual UART Input

After loading the matching firmware, extract the same line from the command
and reference files. For example, from the repository root:

```sh
sed -n '1p' UARTHELPER/FRODODECAPS/decaps_commands_640.txt
sed -n '1p' UARTHELPER/FRODODECAPS/ss_ref_640.txt
sed -n '1p' UARTHELPER/FRODODECAPS/fail_mask_ref_640.txt
sed -n '1p' UARTHELPER/FRODODECAPS/cases_640.jsonl
```

Send the command at 115200 8N1 with a final newline. Wait for `END` before
sending the next line. These commands request cycle counters and the full
algorithm output. Compare hex values case-insensitively.

The largest Decaps command is 129,586 bytes including newline. The board streams it directly into binary buffers; ensure a manual UART tool does not truncate long lines.

Shared source import, coverage inventory and protocol logic are under
[`../FRODO/`](../FRODO/README.md). The independent entry point reads the
files in this directory directly and compares every listed reference field.
