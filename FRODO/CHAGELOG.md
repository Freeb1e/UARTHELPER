# Change Log

## 2026-09-18

- Added explicit `--firmware-tree HWDISPLAY` selection for Frodo board, KAT,
  and independent stage runners; parameter-specific KeyGen/Encaps images are
  selected and missing images fail before JTAG access. BOARDSW stays the default.
- Passed all 17 host tests and official SHAKE KAT count=0 on the physical board
  for optimized HWDISPLAY Frodo KeyGen 640/976/1344, checking complete PK/PKH
  and recording all seven stage counters. Evidence is in root
  `evidence/hwdisplay-frodo-keygen-{640,976,1344}-20260918/`.
- Passed official SHAKE KAT count=0 on the physical board for optimized
  HWDISPLAY Frodo Encaps 640/976/1344, checking complete CT/SS and recording
  all fourteen stage counters. Evidence is in root
  `evidence/hwdisplay-frodo-encaps-{640,976,1344}-20260918/`.
- Passed official SHAKE KAT count=0 on the physical board for optimized
  HWDISPLAY Frodo Decaps 640/976/1344, comparing full SS and `FAIL_MASK=0`
  and recording four stage counters. Evidence is in root
  `evidence/hwdisplay-frodo-decaps-{640,976,1344}-20260918/`.

## 2026-09-13

- Added optional --compact verification to the official KAT and independent
  stage runners: PKH-only KeyGen, SS-only Encaps and SS/mask Decaps. Existing
  firmware print flags suppress PK/CT output; canonical files stay complete.
- Recorded mode and checked fields in reports and revalidated reused results
  against the selected command and references. Compact results do not imply
  full PK/CT comparison. Documented that Decaps still uploads full SK/CT.
- Passed all 15 host tests, including both CLI paths, short fragmented UART
  responses, wrong/missing compact outputs, full-file preservation and reuse
  isolation. All 9 compact physical-board requests passed for official count=0
  across 640/976/1344 and all stages, with no PK/CT fields returned. Evidence:
  root evidence/frodo_compact_20260913. No firmware rebuild was required.

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
