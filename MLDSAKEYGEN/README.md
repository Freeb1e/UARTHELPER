# ML-DSA KeyGen UART helper

`run_keygen_tests.py` builds deterministic PK/SK golden outputs from the
repository's unaccelerated Dilithium reference, sends the same 32-byte seed to
the matching board firmware, and compares the complete returned keys.

See `e203_hbirdv2/scripts/BOARDSW/kd_mldsa_keygen/README.md` for build, upload,
memory-layout and per-parameter commands.

For manual acceptance, line N of `keygen_commands_<parameter>.txt` corresponds
to line N of `pk_ref_<parameter>.txt` and `sk_ref_<parameter>.txt`. The latter
two files contain the complete expected `PK=` and `SK=` outputs. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
