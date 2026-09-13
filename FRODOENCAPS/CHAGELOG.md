# Change Log

## 2026-09-13

- Added independent 640/976/1344 command files with 253/103/105 requests and
  complete line-aligned CT/SS references plus original-source case indexes.
- Replaced SS-only execution with the shared full-output validator and JTAG
  loader. --line selects a command and both corresponding references.
- Stage files pass round-trip validation; shared host tests pass. Full board
  batch results are recorded in evidence/frodo_board_20260913/full_run01.

## 2026-08-27

- Added sequential Frodo Encaps UART test execution, SS extraction, board
  result generation, and byte-for-byte comparison with the supplied reference.
- Added command validation for all Frodo parameter sets, protocol unit tests,
  dependency declaration, and usage documentation.
