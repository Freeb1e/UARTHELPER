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

The former UART firmware has been removed. Reference generation and host UART
protocol tools remain; UART execution requires a separately supplied compatible
device. Current PACE Frodo/Scloud firmware uses DTCM simulation inputs and does
not implement this ML-DSA UART protocol.

`sign_commands_<parameter>.txt` is a compact generation source whose first
long field is a seed, so it must not be sent directly to the board. Manual
acceptance uses `sign_uart_commands_<parameter>.txt`, which contains the full
SK, and the same line of `sig_ref_<parameter>.txt` contains the expected
`SIG=` output. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
