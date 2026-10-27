# ML-DSA KeyGen UART helper

`run_keygen_tests.py` builds deterministic PK/SK golden outputs from the
repository's unaccelerated Dilithium reference, sends the same 32-byte seed to
the matching board firmware, and compares the complete returned keys.

The former UART firmware has been removed. Reference generation and host UART
protocol tools remain; UART execution requires a separately supplied compatible
device. Current PACE Frodo/Scloud firmware uses DTCM simulation inputs and does
not implement this ML-DSA UART protocol.

For manual acceptance, line N of `keygen_commands_<parameter>.txt` corresponds
to line N of `pk_ref_<parameter>.txt` and `sk_ref_<parameter>.txt`. The latter
two files contain the complete expected `PK=` and `SK=` outputs. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
