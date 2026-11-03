# FrodoKEM-SHAKE KAT Vectors And UART Tools

These host tools prepare reference vectors and test the
[HWDISPLAY UART firmware](../../e203_hbirdv2/scripts/HWDISPLAY/README.md).
[SIMDISPLAY](../../e203_hbirdv2/scripts/SIMDISPLAY/README.md) runs the same
commands and response format in the E203 SoC simulation. Both call the current
[PQC-PACE-Frodo core](../../e203_hbirdv2/scripts/PQC-PACE-Frodo/README.md).
Upload the image matching the operation and parameter before running a UART
stage client; the clients do not load firmware automatically.

## Official KAT Preparation

Run from the repository root:

```sh
python3 UARTHELPER/FRODO/run_kat_tests.py \
    --reference-root /home/tomoyo/PQCrypto-LWEKE-master \
    --results /tmp/frodo-kat-inventory
```

This command prepares vectors and a coverage inventory without opening a serial
port or loading firmware. It imports only these files from `FrodoKEM/KAT`:

- `PQCkemKAT_19888_shake.rsp`: 640, counts 0..99.
- `PQCkemKAT_31296_shake.rsp`: 976, counts 0..99.
- `PQCkemKAT_43088_shake.rsp`: 1344, counts 0..99.

The filenames contain secret-key byte lengths, not case counts. These are
reference implementation known-answer vectors, not an official certification.
Random inputs are derived by compiling the supplied `rng.c` and `aes_c.c` into
a temporary host library. Count-0 randomness is cross-checked against the
supplied NIST RNG outputs, and PK/SK relationships and PKH are checked.

The importer writes and verifies the canonical stage files below. Each has
exactly 100 headerless lines per parameter; line N corresponds to official
count N-1. The `cases_P.jsonl` files retain source names and case indices.
The result directory must be new; `summary.json` records `PREPARED` status.

| Stage | Directory | Input files | Reference files |
| --- | --- | --- | --- |
| KeyGen | [FRODOKEYGEN](../FRODOKEYGEN/README.md) | keygen_commands_P.txt | pk_ref_P.txt, pkh_ref_P.txt |
| Encaps | [FRODOENCAPS](../FRODOENCAPS/README.md) | encaps_commands_P.txt | ct_ref_P.txt, ss_ref_P.txt |
| Decaps | [FRODODECAPS](../FRODODECAPS/README.md) | decaps_commands_P.txt | ss_ref_P.txt, fail_mask_ref_P.txt |

P is 640, 976 or 1344. Both command flags are 1, requesting cycle counters
and full output. All supplied official KAT ciphertexts are valid, so their
Decaps failure-mask references are 0.

## UART Stage Clients

The stage entry points accept `--parameter`, `--port`, `--results` and optional
`--line`. They send commands to an already running compatible UART device;
they do not build, upload or select firmware. By default they compare every
reference field and preserve TX/RX transcripts and JSONL outcomes in a new
result directory.

## Compact Batch Verification

Add `--compact` to an independent stage entry point to suppress large outputs.
The default remains full verification.

| Stage | Default comparisons | Compact comparisons | Suppressed UART output |
| --- | --- | --- | --- |
| KeyGen | Complete PK and PKH | PKH | PK |
| Encaps | Complete CT and SS | SS | CT |
| Decaps | Complete SS and FAIL_MASK | Complete SS and FAIL_MASK | None |

After loading the Frodo-640 KeyGen HWDISPLAY image, send a 100-case batch with:

```sh
python3 -u UARTHELPER/FRODOKEYGEN/run_keygen_tests.py \
    --parameter 640 --port /dev/ttyUSB2 --compact \
    --results /tmp/frodo-keygen-640-compact
```

The runner changes the print flag only in memory. Canonical command/reference
files retain full-output commands and references. Counters, acknowledgements,
lengths and Decaps failure masks remain checked. All inputs are transmitted in
full, including Decaps SK and CT. Compact KeyGen checks PKH, and compact Encaps
checks SS; these are not complete PK/CT comparisons. Result records identify
`verification_mode` and `verified_fields`. Omit `--compact` for full output.

## Generated Smoke Vectors

The independent generated set in `vectors/` contains three deterministic cases
per parameter, including valid and tampered Decaps inputs. It is separate from
the official `.rsp` set. These are public test keys. To generate another set:

```sh
python3 -m pip install -r UARTHELPER/FRODO/requirements.txt
python3 UARTHELPER/FRODO/reference_vectors.py \
    --reference-root /home/tomoyo/PQCrypto-LWEKE-master \
    --vectors /tmp/frodo-vectors --count 3
```

Generation requires a new output directory. The default master seed is the
32-byte sequence 00 through 1F; override it with `--seed HEX`. Each parameter
JSON contains random inputs, PK, SK, PKH, CT, SS and a tampered case. Provenance
records source hashes and the master seed. Generated command files describe
the same UART protocol.

Each negative case flips bit 7 of a byte in packed C (byte 9660 for 640,
15744 for 976, or 21568 for 1344). Generation checks the modified ciphertext
with reference Decaps and independently verifies `SHAKE(received_CT || s)`,
using SHAKE128 for 640 and SHAKE256 otherwise.

## Protocol Checks And Historical Evidence

```sh
python3 -m unittest discover -s UARTHELPER/FRODO -p 'test_*.py'
```

The retained tests cover reference preparation and UART parsing/comparison,
including fragmented full-length fields, invalid acknowledgements, duplicates,
partial timeout data, rejection masks and parameter/stage request shapes.
Historical physical-board evidence remains under
[evidence/frodo_board_20260913](../../evidence/frodo_board_20260913/README.md).
