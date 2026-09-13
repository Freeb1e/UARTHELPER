# FrodoKEM-SHAKE Official KAT Board Tests

The current suite tests only the supplied reference repository's official
FrodoKEM-SHAKE KATs. There are 100 records (count 0..99) for each of 640, 976
and 1344: 300 records, each tested through KeyGen, Encaps and Decaps, for
900 board requests. Historical and generated smoke cases are excluded.

## Independent Stage Directories

| Stage | Directory | Input files | Reference files |
| --- | --- | --- | --- |
| KeyGen | [FRODOKEYGEN](../FRODOKEYGEN/README.md) | keygen_commands_P.txt | pk_ref_P.txt, pkh_ref_P.txt |
| Encaps | [FRODOENCAPS](../FRODOENCAPS/README.md) | encaps_commands_P.txt | ct_ref_P.txt, ss_ref_P.txt |
| Decaps | [FRODODECAPS](../FRODODECAPS/README.md) | decaps_commands_P.txt | ss_ref_P.txt, fail_mask_ref_P.txt |

P is 640, 976 or 1344. Every input/reference file has exactly 100 headerless
lines. Line N corresponds to official count N-1 in all three stages.
cases_P.jsonl records that source and index. Both instruction flags are 1:
cycle counters and full output are requested. All supplied KAT ciphertexts
are valid, so every Decaps failure-mask reference is 0.

The stage entry points accept --parameter, --port, --results and optional
--line for a single reproduction. They load the matching ELF through JTAG,
then compare every reference field by default. Shared protocol logic and tests live here;
the canonical UART inputs and references live in the three stage directories.

## Compact Batch Verification

Add `--compact` to any independent stage entry point or `run_kat_tests.py`
to suppress large UART outputs. The default remains full verification.

| Stage | Default comparisons | `--compact` comparisons | Suppressed UART output |
| --- | --- | --- | --- |
| KeyGen | Complete PK and PKH | PKH | PK |
| Encaps | Complete CT and SS | SS | CT |
| Decaps | Complete SS and FAIL_MASK | Complete SS and FAIL_MASK | None; already compact |

For 100 Frodo-640 KeyGen cases:

```sh
.venv/bin/python -u UARTHELPER/FRODOKEYGEN/run_keygen_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --compact \
    --results /tmp/frodo-keygen-640-compact
```

For all 900 official KAT requests:

```sh
.venv/bin/python -u UARTHELPER/FRODO/run_kat_tests.py \
    --reference-root /home/tomoyo/PQCrypto-LWEKE-master \
    --port /dev/ttyUSB2 --compact --results /tmp/frodo-kat-compact
```

`--line N` still selects one case in an independent stage. Result directories
must be new. No firmware rebuild is required: KeyGen and Encaps already support
the print flag being zero. The runner changes that flag only in memory; the
canonical command/reference files retain full-output commands and references.
Cycle counters, acknowledgements, lengths and Decaps failure masks remain checked.

All inputs are still transmitted in full. In particular, Decaps still uploads
the complete SK and CT, so this mode does not materially reduce its UART time.
KeyGen PKH verification checks the public-key hash; compact Encaps checks the
shared secret. Neither is reported as a complete PK/CT byte comparison. For a
full reproduction, omit `--compact` and use the same input line.

`summary.json` and each result record identify `verification_mode` as `full`
or `compact`; records also list `verified_fields`. Reuse validates the actual
command hash and the selected reference fields again. Compact KeyGen/Encaps
results cannot be reused as full-output results because their commands differ.
Decaps checks and commands are identical in both modes and can be revalidated
for either mode. These options apply to the official and independent stage
runners; the archived `run_board_tests.py test` smoke suite remains full-output.

## All Official KATs

With the accelerator bitstream loaded and the five ELF images built as below:

```sh
.venv/bin/python -u UARTHELPER/FRODO/run_kat_tests.py \
    --reference-root /home/tomoyo/PQCrypto-LWEKE-master \
    --results /tmp/frodo-official-kat
```

The runner imports only these files from FrodoKEM/KAT:

- PQCkemKAT_19888_shake.rsp: 640, counts 0..99.
- PQCkemKAT_31296_shake.rsp: 976, counts 0..99.
- PQCkemKAT_43088_shake.rsp: 1344, counts 0..99.

The filenames contain SK byte lengths, not case counts. These are known-answer
vectors provided by the reference implementation; passing them is not an
official certification.

KAT random inputs are derived by compiling the supplied rng.c and aes_c.c as
a temporary host library. Count-0 randomness is cross-checked with the supplied
NISTKAT.NISTRNG known outputs. PK/SK relationships and PKH are checked before
hardware access. The importer rewrites the per-stage files from official
inputs and verifies their round trip before running any commands.

Results include source/artifact hashes, all expected batch counts, complete
TX/RX transcripts and per-request JSONL outcomes. summary.json tracks actual
progress and completion. Use --prepare-only to export/check inputs without
opening hardware.

For an interrupted run, --reuse-results PATH/TO/results.jsonl accepts only
matching official KAT records with PASS status. It rechecks the selected
reference fields, command hash and current ELF hash; duplicates or mismatches fail.
Copied records retain the original evidence path and line. Unrelated historical
records are not imported.

The current physical-board run and its acceptance scope are recorded under
[evidence/frodo_board_20260913](../../evidence/frodo_board_20260913/README.md).

## Archived Initial Acceptance Set

The earlier smoke suite covers 640, 976 and 1344 with three deterministic cases per
parameter. It uses the supplied PQCrypto-LWEKE Python generator and reference
implementation. The committed vectors contain public test keys.

| Stage | Requests per parameter | Required comparisons |
| --- | ---: | --- |
| KeyGen | 3 | Complete PK and PKH |
| Encaps | 3 | Complete CT and SS |
| Decaps | 6 | Complete SS and FAIL_MASK, valid and tampered CT |

The same case randomness and reference outputs connect all three stages:
the board PK must equal the reference PK supplied to Encaps, and the board CT
must equal the reference CT supplied to Decaps. KeyGen does not export SK;
Decaps uses the corresponding official reference SK.

## Setup and vectors

Run from the merged repository root:

```sh
.venv/bin/python -m pip install -r UARTHELPER/FRODO/requirements.txt
.venv/bin/python UARTHELPER/FRODO/run_board_tests.py generate \
    --reference-root /home/tomoyo/PQCrypto-LWEKE-master \
    --vectors /tmp/frodo-vectors --count 3
```

Generation requires a new output directory. The default master seed is the
32-byte sequence 00 through 1F; override it with `--seed HEX`. Each parameter
JSON contains all random inputs, PK, SK, PKH, CT, SS and the tampered case.
The provenance file records the reference source hashes and master seed.
The nine `*_commands_<parameter>.txt` files can also be used as UART input.
The existing generated set is in `vectors/`.

Each negative case flips bit 7 of a byte in packed C (byte 9660 for 640,
15744 for 976, or 21568 for 1344). Generation checks the modified ciphertext
with official software Decaps and independently verifies that its SS is
`SHAKE(received_CT || s)`, using SHAKE128 for 640 and SHAKE256 otherwise.

## Build and test the FPGA

```sh
make -C e203_hbirdv2/scripts/BOARDSW/frodo_keygen check-image
make -C e203_hbirdv2/scripts/BOARDSW/frodo_encaps check-image
for p in 640 976 1344; do
    make -C e203_hbirdv2/scripts/BOARDSW/frodo_decaps check-image \
        FRODO_PARAMETER="$p" || break
done
.venv/bin/python -u UARTHELPER/FRODO/run_board_tests.py test \
    --port /dev/ttyUSB2 --vectors UARTHELPER/FRODO/vectors \
    --results /tmp/frodo-board-results
```

The runner loads and verifies each ELF through the installed NucleiStudio
OpenOCD, resumes the CPU, checks the UART READY banner and executes requests
sequentially at 115200 8N1. This replaces the volatile CPU program in ILM;
it uses the already loaded accelerator bitstream. Override the executable
with `--openocd PATH`. It shares the existing ILM JTAG configuration under
`scloud_encaps/`.

Use `--parameters 976` or `--operations decaps` for a focused rerun.
The result directory must be new, preserving previous debug attempts.
Every request is checkpointed in `results.json`; per-stage text files retain
OpenOCD verification, firmware startup, complete TX/RX and partial timeout
data. A malformed response, wrong output, missing cycle count or hardware
error stops the run. Firmware SHA256 is included in each result.

Algorithm cycle counts exclude UART input/output. `CPU_HZ` reports the SDK's
startup-measured CPU frequency; time in ms is cycles * 1000 / CPU_HZ.
The final firmware remains running on the board.

## Local checks

```sh
.venv/bin/python -m unittest discover -s UARTHELPER/FRODO -p 'test_*.py'
cc -std=c99 -Wall -Wextra -Werror \
    e203_hbirdv2/scripts/sw/tests/frodo_secret_codec_test.c \
    -o /tmp/frodo_secret_codec_test
/tmp/frodo_secret_codec_test
```

The protocol tests cover fragmented full-length fields, wrong acknowledgements,
duplicates, partial timeout data, complete output comparison, rejection masks
and all parameter/stage request shapes. The C test exhausts the LE16 secret
coefficient conversion, including rejection of unrepresentable values.

Physical-board debug and acceptance evidence is recorded in
[`evidence/frodo_board_20260913/`](../../evidence/frodo_board_20260913/README.md).
