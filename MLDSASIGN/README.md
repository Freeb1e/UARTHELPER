# ML-DSA Sign UART helper

`run_sign_tests.py` derives a test secret key from each compact KeyGen seed,
builds the expected randomized signature with the repository's unaccelerated
Dilithium reference, sends the full SK/message/random input to the matching
board firmware, and compares every signature byte.

See `e203_hbirdv2/scripts/BOARDSW/kd_mldsa_sign/README.md` for build, upload,
memory-layout and per-parameter commands.
