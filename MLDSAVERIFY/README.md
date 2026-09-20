# ML-DSA Verify UART helper

`run_verify_tests.py` derives deterministic test keys and signatures with the
repository's unaccelerated Dilithium reference. It sends each valid signature
and a single-bit-tampered counterpart to the board and compares the acceptance
decision.

See `e203_hbirdv2/scripts/BOARDSW/kd_mldsa_verify/README.md` for build, upload,
memory-layout and per-parameter commands.

`verify_commands_<parameter>.txt` is a compact generation source. Manual
acceptance uses `verify_uart_commands_<parameter>.txt`, containing the complete
PK/message/signature, and compares the same line of `valid_ref_<parameter>.txt`
with the board's `VALID=` output. Each source expands to a valid line followed
by a tampered line. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
