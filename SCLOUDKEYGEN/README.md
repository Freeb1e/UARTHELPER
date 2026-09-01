# Scloud+ KeyGen UART tests

`run_keygen_tests.py` reads canonical Scloud+ KAT records directly from
`Scloud+/Test_Vectors`. For each record it sends the file's parameter and only
`Seed` as cryptographic input, waits for `END`, and compares the returned
complete `PK` and `SK` values with that same record. A malformed response,
board error, timeout, or first mismatch stops the run immediately.

The current production board firmware supports the `128-SM3`, `192-SM3`, and
`256-SM3` files in one image. The tool reads the parameter from the KAT
filename and sends it with every request, so switching among these files does
not require rebuilding or reloading the firmware.

From `/home/tomoyo/project`, install the serial dependency and run the default
128-SM3 vectors with:

```sh
python3 -m pip install -r UARTHELPER/SCLOUDKEYGEN/requirements.txt
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py --port /dev/ttyUSB0
```

When the current directory is `/home/tomoyo/project/UARTHELPER`, use:

```sh
python3 -m pip install -r SCLOUDKEYGEN/requirements.txt
python3 SCLOUDKEYGEN/run_keygen_tests.py --port /dev/ttyUSB0
```

Select another supported canonical file:

```sh
python3 UARTHELPER/SCLOUDKEYGEN/run_keygen_tests.py \
    --port /dev/ttyUSB0 \
    --vectors Scloud+/Test_Vectors/KAT_KEM_Scloudplus-256-SM3-packed10.txt
```

The link is 115200 8N1. `--timeout` defaults to 120 seconds per vector because
the response includes full keys. Run parser/protocol tests without a board:

```sh
python3 -m unittest discover -s UARTHELPER/SCLOUDKEYGEN -p 'test_*.py'
```
