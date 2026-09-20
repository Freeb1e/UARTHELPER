# ML-KEM Decaps UART helper

`run_decaps_tests.py` generates deterministic KeyGen and Encaps results with
the repository's unaccelerated reference. For every base input it creates one
valid ciphertext and one single-bit-tampered ciphertext, sends the complete SK
and CT to the matching board image, and compares all 32 shared-secret bytes.

See `e203_hbirdv2/scripts/BOARDSW/kd_mlkem_decaps/README.md` for the build,
upload and per-security-level commands.

For manual acceptance, use `decaps_commands_<parameter>.txt`; each line is a
complete board command and the same line of `ss_ref_<parameter>.txt` is its
expected `SS=` output. Each compact source input expands to a valid line and
then a tampered line. See the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
