# Scloud+ KeyGen UART tests

`run_keygen_tests.py` reads canonical Scloud+ KAT records directly from
`third_party/Scloud+/Test_Vectors`. For each record it derives `z` and `alpha`
from `Seed` on the host and sends `KEYGEN <parameter> <z||alpha_hex>`, waits
for `END`, and compares the returned
complete `PK` and `SK` values with that same record. A malformed response,
board error, timeout, or first mismatch stops the run immediately.

The current production board firmware supports the `128-SM3`, `192-SM3`, and
`256-SM3` files in one image. The tool reads the parameter from the KAT
filename and sends it with every request, so switching among these files does
not require rebuilding or reloading the firmware.

The host requires `cc` (a C compiler). Each run builds a temporary helper using
the merged repository's official `Implementations/_shared/api_pkc/drng.c`.
It initializes DRNG separately for each seed, then draws 64 bytes for `z` and
64 bytes for `alpha` in two calls. No DRNG implementation is duplicated in Python.
Use the version-3 board firmware; the previous Seed-only protocol is removed.

From the merged repository root, install the serial dependency and run the default
128-SM3 vectors with:

```sh
python3 -m pip install -r UARTHELPER/SCLOUDKEYGEN/requirements.txt
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py --port /dev/ttyUSB0
```

When the current directory is the repository's `UARTHELPER` directory, use:

```sh
python3 -m pip install -r SCLOUDKEYGEN/requirements.txt
python3 SCLOUDKEYGEN/run_keygen_tests.py --port /dev/ttyUSB0
```

Select another supported canonical file:

```sh
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
    --port /dev/ttyUSB0 \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt
```

The default vector path is resolved relative to the script location. An explicit
`--vectors` path is relative to the current working directory; from `UARTHELPER`,
use `../third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt`.

The link is 115200 8N1. `--timeout` defaults to 120 seconds per vector because
the response includes full keys.

Every response displays all reported `CYCLES_*` stages before the PK/SK
comparison result. DRNG runs only on the host. The debug board
image reports `COMPACT_B` (physical-to-protocol column compaction) separately
from `PACK_PK` (Pack10 and seedA append); add these two stages when comparing
with the older combined `PACK_PK` measurement. For parameter 128, compaction
is a no-op, so its count only reflects the call/check overhead.

To also display milliseconds, supply the actual CPU clock with `--cpu-mhz`.
For example, for a board running at 100 MHz, from the repository root:

```sh
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
    --port /dev/ttyUSB0 --cpu-mhz 100 \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt
```

The frequency option only controls host-side conversion; it does not set the
board clock. Without it the report shows measured cycles only. All board
debug printing occurs after algorithm timing, so UART output is excluded.

Generate commands before connecting the board (no serial dependency needed):

```sh
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt \
    --commands-out UARTHELPER/SCLOUDKEYGEN/keygen_commands_256.txt
```

Each line contains the parameter and 128-byte `z || alpha` input. It can be sent
directly from a serial terminal. Add `--port /dev/ttyUSB0` to the same command to
both export and run automatic full PK/SK comparisons. Command files are KAT test
data; `z` and `alpha` are deterministic random inputs, not TRNG output.

Prepared command files for all three supported SM3 parameter sets (10 records each):

- [128](keygen_commands_128.txt)
- [192](keygen_commands_192.txt)
- [256](keygen_commands_256.txt)

Run all three sets sequentially on the same board image from the repository root:

```sh
for parameter in 128 192 256; do
    python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
        --port /dev/ttyUSB2 \
        --vectors "third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-${parameter}-SM3-packed10.txt" \
        || break
done
```

Replace the serial path with the connected board's device.

Run parser/protocol tests without a board:

```sh
python3 -m unittest discover -s UARTHELPER/SCLOUDKEYGEN -p 'test_*.py'
```
