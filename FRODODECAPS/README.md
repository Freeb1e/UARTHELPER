# Frodo decaps UART vectors

Load the matching parameter's Decaps
[HWDISPLAY UART image](../../e203_hbirdv2/scripts/HWDISPLAY/README.md) before
running this host tool. [SIMDISPLAY](../../e203_hbirdv2/scripts/SIMDISPLAY/README.md)
accepts the same commands in simulation. Both use the current
[PACE core](../../e203_hbirdv2/scripts/PQC-PACE-Frodo/README.md).

Current RTL validation and its scope are recorded in the
[E203 logic/software acceptance](../../Delivery/E203逻辑软件完整验收.md).
The [earlier 1,032-request board run](../../evidence/uarthelper_fs_full_20261105_162832/README.md)
predates the current RTL optimizations; its results do not establish board
acceptance of the current RTL.

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

Run from the repository root with a compatible UART device already running:

```sh
.venv/bin/python -u UARTHELPER/FRODODECAPS/run_decaps_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --results /tmp/frodo-decaps-640
```

The script sends this stage's commands without loading a CPU image. Results
must use a new directory, which receives complete UART transcripts and JSONL
outcomes. Use `--line 1` to run only the first input and its reference, or
another line number to reproduce an individual case.

`--compact` is accepted for consistency with KeyGen and Encaps:

```sh
.venv/bin/python -u UARTHELPER/FRODODECAPS/run_decaps_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --compact \
    --results /tmp/frodo-decaps-640-compact
```

Decaps already returns only SS, FAIL_MASK and counters, so both modes send
`DECAPS <parameter> 1 1 ...` and perform the same checks. The complete SK and CT
must still be uploaded; this option does not materially reduce Decaps UART time.
Results record compact mode and the checked SS/FAIL_MASK fields. See the shared
[compact-mode details](../FRODO/README.md#compact-batch-verification).

## Manual UART Input

For a compatible UART device, extract the same line from the command and
reference files. For example, from the repository root:

```sh
sed -n '1p' UARTHELPER/FRODODECAPS/decaps_commands_640.txt
sed -n '1p' UARTHELPER/FRODODECAPS/ss_ref_640.txt
sed -n '1p' UARTHELPER/FRODODECAPS/fail_mask_ref_640.txt
sed -n '1p' UARTHELPER/FRODODECAPS/cases_640.jsonl
```

Send the command at 115200 8N1 with a final newline. Wait for `END` before
sending the next line. These commands request cycle counters and the full
algorithm output. Compare hex values case-insensitively.

The largest Decaps command is 129,586 bytes including newline; ensure the
UART device and manual tool can accept the complete line without truncation.

Shared source import, coverage inventory and protocol logic are under
[`../FRODO/`](../FRODO/README.md). The independent entry point reads the
files in this directory directly and compares every listed reference field.
