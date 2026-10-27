# ML-KEM Encaps UART helper

`run_encaps_tests.py` builds deterministic golden outputs from the repository's
unaccelerated Kyber reference, sends each public key and 32-byte Encaps input
to the matching board firmware, and compares the complete ciphertext and
shared secret.

The former UART firmware has been removed. Reference generation and host UART
protocol tools remain; UART execution requires a separately supplied compatible
device. Current PACE Frodo/Scloud firmware uses DTCM simulation inputs and does
not implement this ML-KEM UART protocol.

The three `encaps_inputs_<parameter>.txt` files each contain three compact
records. A record stores 64 KeyGen bytes used by the host to derive the public
key and 32 Encaps bytes sent to the board. It deliberately avoids checking in
three copies of each long public key.

For manual acceptance, use the generated `encaps_commands_<parameter>.txt`,
not the compact input file. The complete expected outputs are on the same line
in `ct_ref_<parameter>.txt` and `ss_ref_<parameter>.txt`. Generation and
single-line extraction are documented in the
[shared manual-vector guide](../MANUAL_VECTOR_ACCEPTANCE_CN.md).
