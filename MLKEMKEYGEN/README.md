# KD ML-KEM KeyGen UART helper

The former UART firmware has been removed. Reference generation and host UART
protocol tools remain; UART execution requires a separately supplied compatible
device. Current PACE Frodo/Scloud firmware uses DTCM simulation inputs and does
not implement this ML-KEM UART protocol.

Quick host-only check:

```sh
python3 run_keygen_tests.py --parameter 512 --golden-only
python3 -m unittest discover -s . -p 'test_*.py'
```

For an already running compatible UART device:

```sh
python3 run_keygen_tests.py --port /dev/ttyUSB2 --parameter 512 --cpu-mhz 100
```

For manual acceptance, `keygen_commands_<parameter>.txt` is directly
sendable. The same line in `pk_ref_<parameter>.txt` and
`sk_ref_<parameter>.txt` contains the complete expected output. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
