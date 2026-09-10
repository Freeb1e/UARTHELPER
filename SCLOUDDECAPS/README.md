# Scloud+ Decaps UART tests

The runner sends official KAT SK and CT directly to the board. Decapsulation
requires no DRNG. Each parameter run checks all 10 canonical valid records,
then flips bit 7 of the last CT byte of Count 0 and checks implicit rejection.
Valid SS must match the complete KAT value and FAIL_MASK must be 0. The
tampered SS must match K(z || modified_CT), and FAIL_MASK must be 255.

The host uses Python hashlib's SM3 implementation for the one-block labeled
K output (16/24/32 bytes), and reuses existing Scloud KAT/serial/report helpers.
Requires Python 3.10+ with SM3 support and pyserial for board access.

Generate all three command files from the repository root:

```sh
for p in 128 192 256; do
    python3 UARTHELPER/SCLOUDDECAPS/run_decaps_tests.py \
        --vectors "third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-${p}-SM3-packed10.txt" \
        --commands-out "UARTHELPER/SCLOUDDECAPS/decaps_commands_${p}.txt" || break
done
```

Each file contains 11 `DECAPS <parameter> <sk_hex> <ct_hex>` commands. The first
10 are valid KATs; the last is the tampered Count 0 case. These are public KAT
test keys. Load the matching [parameter image](../../e203_hbirdv2/scripts/BOARDSW/scloud_decaps/README.md)
before running the test:

```sh
python3 -m pip install -r UARTHELPER/SCLOUDKEYGEN/requirements.txt
python3 -u UARTHELPER/SCLOUDDECAPS/run_decaps_tests.py \
    --port /dev/ttyUSB2 \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt
```

Use the actual connected serial device. The link is 115200 8N1; timeout is
120 seconds by default. All stage cycles are displayed with milliseconds
converted using the board's startup-measured CPU_HZ. The run stops at the first
SS/mask mismatch, malformed response, hardware error or timeout.

```sh
python3 -m unittest discover -s UARTHELPER/SCLOUDDECAPS -p 'test_*.py'
```
