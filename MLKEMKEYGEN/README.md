# KD ML-KEM KeyGen UART helper

The complete beginner-oriented build, upload, UART protocol and automatic test
walkthrough is in
[`e203_hbirdv2/scripts/BOARDSW/kd_mlkem_keygen/README.md`](../../e203_hbirdv2/scripts/BOARDSW/kd_mlkem_keygen/README.md).

Quick host-only check:

```sh
python3 run_keygen_tests.py --parameter 512 --golden-only
python3 -m unittest discover -s . -p 'test_*.py'
```

Quick board run after loading the matching image:

```sh
python3 run_keygen_tests.py --port /dev/ttyUSB2 --parameter 512 --cpu-mhz 100
```

For manual acceptance, `keygen_commands_<parameter>.txt` is directly
sendable. The same line in `pk_ref_<parameter>.txt` and
`sk_ref_<parameter>.txt` contains the complete expected output. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
