# Change Log

## 2026-09-13

- Added all-existing-vector execution and three independent stage packages:
  409 KeyGen, 461 Encaps and 418 Decaps requests across all parameters.
  Includes official SHAKE KATs and historical vectors with duplicate-source
  accounting, complete references and source/line indexes.
- Reused the official C KAT RNG, checked historical HEX copies, and verified
  Encaps-only reference inputs before hardware access.
- All 11 current shared protocol, import/export and independent CLI tests pass.
  The later official-only scope replaces the mixed-source batch: each stage
  now has 100 commands per parameter; run_kat_tests.py imports only official
  SHAKE KATs and validates previous matching KAT evidence before reuse.
  All 12 current host tests pass; the 900-request KAT run is in progress.

- Added complete FrodoKEM-SHAKE 640/976/1344 board acceptance using the supplied
  official Python generator, with three reproducible cases per parameter.
- Added all nine parameter/stage command files and complete reference fields.
  KeyGen compares PK and PKH; Encaps compares CT and SS; Decaps compares SS
  and failure mask for both valid and tampered ciphertexts.
- Added automatic JTAG ELF load/verify, READY checks, full UART transcripts,
  checkpointed JSON results, firmware identities and stage cycle capture.
- Passed 36 physical-board requests in the final run, all six protocol tests,
  and the board secret codec's exhaustive 65,536-input check.
- Retained the initial SK-format conversion failure and its successful
  correction in the root evidence/frodo_board_20260913 directory.
