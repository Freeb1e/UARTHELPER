# Scloud+ Encaps board KATs

Load the matching parameter's Encaps
[HWDISPLAY UART image](../../e203_hbirdv2/scripts/HWDISPLAY/README.md) before
running this host tool. [SIMDISPLAY](../../e203_hbirdv2/scripts/SIMDISPLAY/README.md)
accepts the same commands in simulation. Both use the current
[PACE core](../../e203_hbirdv2/scripts/PQC-PACE-Scloud/README.md) for 128/192/256.
Parameter-512 vectors require a separately supplied compatible device.

The runner reads the merged repository's canonical 128/192/256/512-SM3 packed10
KATs, invokes the official `api_pkc/drng.c` on the host, and sends PK and message
m to the board. DRNG state follows the official KAT sequence: initialize Seed,
draw z, draw alpha, then draw parameter/8-byte m. The first two draws are 64
bytes for the lower sets and 128 bytes for parameter 512. It compares
every returned CT and SS byte and stops at the first error or mismatch.

Requires Python 3.10+, a host C compiler `cc`, and pyserial for board testing.
Serial opening, KAT key parsing and cycle formatting reuse SCLOUDKEYGEN helpers.

```sh
python3 -m pip install -r UARTHELPER/SCLOUDKEYGEN/requirements.txt
```

Generate all command files without a board:

```sh
for p in 128 192 256 512; do
    python3 UARTHELPER/SCLOUDENCAPS/run_encaps_tests.py \
        --vectors "third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-${p}-SM3-packed10.txt" \
        --commands-out "UARTHELPER/SCLOUDENCAPS/encaps_commands_${p}.txt" || break
done
```

Each file contains 10 complete `ENCAPS <parameter> <pk_hex> <message_hex>`
commands. These are deterministic test inputs, not TRNG output.

`ct_ref_<parameter>.txt` and `ss_ref_<parameter>.txt` contain the complete
expected `CT=` and `SS=` values in exactly the same line order. See the
[manual acceptance guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md) for extracting
one command/reference tuple and checking all generated files.

After uploading the Scloud+128 Encaps HWDISPLAY image:

```sh
python3 -u UARTHELPER/SCLOUDENCAPS/run_encaps_tests.py \
    --port /dev/ttyUSB2 \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-128-SM3-packed10.txt
```

Use the connected board's actual serial path. The link is 115200 8N1; response
timeout defaults to 120 seconds. Milliseconds are converted from measured
cycles using `CPU_HZ` returned by the firmware: its configured build frequency,
20 MHz by default. Set the firmware's `CPU_HZ` build option to the board's clock.
Host DRNG and UART transfer are excluded from algorithm timing.

```sh
python3 -m unittest discover -s UARTHELPER/SCLOUDENCAPS -p 'test_*.py'
```
