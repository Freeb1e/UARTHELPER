# ML-DSA Sign UART helper

`run_sign_tests.py` derives a test secret key from each compact KeyGen seed,
builds the expected randomized signature with the repository's unaccelerated
Dilithium reference, sends the full SK/message/random input to the matching
hardware or E203-software board firmware, and compares every signature byte.
It can save successful per-case measurements as CSV.

`compare_sign_measurements.py` accepts one hardware CSV and its paired software
CSV. It verifies identical inputs, signatures and rejection-attempt counts,
then reports total-workload and per-attempt-group speedups.

Generated performance batches can use repeatable `--benchmark-skip INDEX`
arguments. The requested output count is preserved by deriving later indexes,
so both board implementations must use exactly the same skip arguments.

See `e203_hbirdv2/scripts/BOARDSW/kd_mldsa_sign/README.md` for build, upload,
memory-layout and per-parameter commands.

`sign_commands_<parameter>.txt` is a compact generation source whose first
long field is a seed, so it must not be sent directly to the board. Manual
acceptance uses `sign_uart_commands_<parameter>.txt`, which contains the full
SK, and the same line of `sig_ref_<parameter>.txt` contains the expected
`SIG=` output. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
