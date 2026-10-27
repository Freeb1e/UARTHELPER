# ML-DSA Verify UART helper

`run_verify_tests.py` derives deterministic test keys and signatures with the
repository's unaccelerated Dilithium reference. It sends each valid signature
and a single-bit-tampered counterpart to the board and compares the acceptance
decision.

The former UART firmware has been removed. Reference generation and host UART
protocol tools remain; UART execution requires a separately supplied compatible
device. Current PACE Frodo/Scloud firmware uses DTCM simulation inputs and does
not implement this ML-DSA UART protocol.

`verify_commands_<parameter>.txt` is a compact generation source. Manual
acceptance uses `verify_uart_commands_<parameter>.txt`, containing the complete
PK/message/signature, and compares the same line of `valid_ref_<parameter>.txt`
with the board's `VALID=` output. Each source expands to a valid line followed
by a tampered line. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
