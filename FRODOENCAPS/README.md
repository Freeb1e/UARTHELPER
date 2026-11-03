# Frodo encaps UART vectors

Load the matching parameter's Encaps
[HWDISPLAY UART image](../../e203_hbirdv2/scripts/HWDISPLAY/README.md) before
running this host tool. [SIMDISPLAY](../../e203_hbirdv2/scripts/SIMDISPLAY/README.md)
accepts the same commands in simulation. Both use the current
[PACE core](../../e203_hbirdv2/scripts/PQC-PACE-Frodo/README.md).

This directory contains only official KAT encaps inputs and references for
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

- `encaps_commands_P.txt`: complete newline-terminated UART instructions.
- `ct_ref_P.txt` and `ss_ref_P.txt`: one expected value per instruction.
- `cases_P.jsonl`: 1-based line number, source file, original case index and
  valid label (all official KAT ciphertexts are valid). Case index 0 is distinct from command line 1.

CT includes the complete ciphertext and salt. Both CT and SS are checked by default.

## Independent Run

Run from the repository root with a compatible UART device already running:

```sh
.venv/bin/python -u UARTHELPER/FRODOENCAPS/run_encaps_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --results /tmp/frodo-encaps-640
```

The script sends this stage's commands without loading a CPU image. Results
must use a new directory, which receives complete UART transcripts and JSONL
outcomes. Use `--line 1` to run only the first input and its reference, or
another line number to reproduce an individual case.

Add `--compact` for SS-only verification without transmitting the output CT:

```sh
.venv/bin/python -u UARTHELPER/FRODOENCAPS/run_encaps_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --compact \
    --results /tmp/frodo-encaps-640-compact
```

The runner sends `ENCAPS <parameter> 1 0 ...`; the input PK is still transmitted
in full. Input/reference files remain unchanged, and cycle counters are retained.
Results record compact mode and the checked SS field. Omit `--compact` to compare
the complete CT as well. See the shared
[compact-mode details](../FRODO/README.md#compact-batch-verification).

## Manual UART Input

For a compatible UART device, extract the same line from the command and
reference files. For example, from the repository root:

```sh
sed -n '1p' UARTHELPER/FRODOENCAPS/encaps_commands_640.txt
sed -n '1p' UARTHELPER/FRODOENCAPS/ct_ref_640.txt
sed -n '1p' UARTHELPER/FRODOENCAPS/ss_ref_640.txt
sed -n '1p' UARTHELPER/FRODOENCAPS/cases_640.jsonl
```

Send the command at 115200 8N1 with a final newline. Wait for `END` before
sending the next line. These commands request cycle counters and the full
algorithm output. Compare hex values case-insensitively.

These are long ASCII commands/outputs; ensure a manual UART tool does not truncate them.

Shared source import, coverage inventory and protocol logic are under
[`../FRODO/`](../FRODO/README.md). The independent entry point reads the
files in this directory directly and compares every listed reference field by default.
