# Scloud+ Encaps board KATs

The runner reads the merged repository's canonical 128/192/256-SM3 packed10
KATs, invokes the official `api_pkc/drng.c` on the host, and sends PK and message
m to the board. DRNG state follows the official KAT sequence: initialize Seed,
draw 64-byte z, draw 64-byte alpha, then draw parameter/8-byte m. It compares
every returned CT and SS byte and stops at the first error or mismatch.

Requires Python 3.10+, a host C compiler `cc`, and pyserial for board testing.
Serial opening, KAT key parsing and cycle formatting reuse SCLOUDKEYGEN helpers.

```sh
python3 -m pip install -r UARTHELPER/SCLOUDKEYGEN/requirements.txt
```

Generate all command files without a board:

```sh
for p in 128 192 256; do
    python3 UARTHELPER/SCLOUDENCAPS/run_encaps_tests.py \
        --vectors "third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-${p}-SM3-packed10.txt" \
        --commands-out "UARTHELPER/SCLOUDENCAPS/encaps_commands_${p}.txt" || break
done
```

Each file contains 10 complete `ENCAPS <parameter> <pk_hex> <message_hex>`
commands. These are deterministic test inputs, not TRNG output.

Load the matching [board image](../../e203_hbirdv2/scripts/BOARDSW/scloud_encaps/README.md)
before running each parameter. For example, after loading the 256 image:

```sh
python3 -u UARTHELPER/SCLOUDENCAPS/run_encaps_tests.py \
    --port /dev/ttyUSB2 \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt
```

Use the connected board's actual serial path. The link is 115200 8N1; response
timeout defaults to 120 seconds. Milliseconds are converted from measured
cycles using CPU_HZ returned by the firmware (its startup timer-based estimate).
Host DRNG and UART transfer are excluded from algorithm timing.

```sh
python3 -m unittest discover -s UARTHELPER/SCLOUDENCAPS -p 'test_*.py'
```
