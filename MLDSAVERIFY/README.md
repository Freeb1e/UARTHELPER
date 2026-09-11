# ML-DSA Verify UART helper

`run_verify_tests.py` derives deterministic test keys and signatures with the
repository's unaccelerated Dilithium reference. It sends each valid signature
and a single-bit-tampered counterpart to the board and compares the acceptance
decision.

See `e203_hbirdv2/scripts/BOARDSW/kd_mldsa_verify/README.md` for build, upload,
memory-layout and per-parameter commands.
