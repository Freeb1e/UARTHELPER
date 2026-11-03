# Scloud+ KeyGen UART tests

Load the matching parameter's KeyGen
[HWDISPLAY UART image](../../e203_hbirdv2/scripts/HWDISPLAY/README.md) before
running this host tool. [SIMDISPLAY](../../e203_hbirdv2/scripts/SIMDISPLAY/README.md)
accepts the same commands in simulation. Both use the current
[PACE core](../../e203_hbirdv2/scripts/PQC-PACE-Scloud/README.md) for 128/192/256.
Parameter-512 vectors require a separately supplied compatible device.

`run_keygen_tests.py` reads canonical Scloud+ KAT records directly from
`third_party/Scloud+/Test_Vectors`. For each record it derives `z` and `alpha`
from `Seed` on the host and sends `KEYGEN <parameter> <z||alpha_hex>`, waits
for `END`, and compares the returned
complete `PK` and `SK` values with that same record. A malformed response,
board error, timeout, or first mismatch stops the run immediately.

The tool reads the parameter from the KAT filename and constructs the matching
UART request for 128/192/256/512-SM3.

The host requires `cc` (a C compiler). Each run builds a temporary helper using
the merged repository's official `Implementations/_shared/api_pkc/drng.c`.
It initializes DRNG separately for each seed, then draws `z` and `alpha` in
two calls. Each draw is 64 bytes for parameters 128/192/256 and 128 bytes for
parameter 512. No DRNG implementation is duplicated in Python.
The client uses the version-3 protocol with explicit `z || alpha` inputs.

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

For a separately supplied UART device supporting parameter 512:

```sh
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
    --port /dev/ttyUSB0 \
    --vectors third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-512-SM3-packed10.txt
```

The default vector path is resolved relative to the script location. An explicit
`--vectors` path is relative to the current working directory; from `UARTHELPER`,
use `../third_party/Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt`.

The link is 115200 8N1. `--timeout` defaults to 120 seconds per vector because
the response includes full keys.

Every response displays all reported `CYCLES_*` stages before the PK/SK
comparison result. DRNG runs only on the host. The current PACE image reports
`EXPAND_F`, `HARDWARE_CHAIN`, `PACK_AND_SECRET`, `HASH_PK`, `CLEANUP` and
`ALGORITHM_TOTAL`, matching its actual API timing boundaries.

To also display milliseconds, supply the actual CPU clock with `--cpu-mhz`.
For example, for a board running at the default 20 MHz, from the repository root:

```sh
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
    --port /dev/ttyUSB0 --cpu-mhz 20 \
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

Each line contains the parameter and `z || alpha`: 128 bytes total for the
three lower sets and 256 bytes for parameter 512. It can be sent directly from
a serial terminal. Add `--port /dev/ttyUSB0` to the same command to
both export and run automatic full PK/SK comparisons. Command files are KAT test
data; `z` and `alpha` are deterministic random inputs, not TRNG output.

Prepared command files for all supported SM3 parameter sets (10 records each):

- [128](keygen_commands_128.txt)
- [192](keygen_commands_192.txt)
- [256](keygen_commands_256.txt)
- [512](keygen_commands_512.txt)

The matching complete public and secret keys are stored in `pk_ref_<parameter>.txt`
and `sk_ref_<parameter>.txt`. Line N in both files is the expected `PK=`/`SK=`
output for line N of the command file. See the shared
[manual acceptance guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md) for single-line
extraction and regeneration.

Upload the matching image before each parameter's run. From the repository root,
with the board's OpenOCD connection configured:

```sh
for parameter in 128 192 256; do
    make -C e203_hbirdv2/scripts/HWDISPLAY upload \
        ALGORITHM=scloud PARAMETER="$parameter" OPERATION=keygen || break
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
