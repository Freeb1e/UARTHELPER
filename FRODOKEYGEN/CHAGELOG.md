# Change Log

## 2026-09-13

- Added independent 640/976/1344 command files with 203/103/103 requests and
  complete line-aligned PK/PKH references plus original-source case indexes.
- Replaced PKH-only execution with the shared full-output validator and JTAG
  loader. --line selects a command and both corresponding references.
- Stage files pass round-trip validation; shared host tests pass. Full board
  batch results are recorded in evidence/frodo_board_20260913/full_run01.

## 2026-08-27

- Added sequential Frodo KeyGen UART test execution, PKH extraction, result
  file generation, and byte-for-byte comparison with the reference file.
- Added protocol unit tests and usage documentation.
- Clarified dependency installation and test commands when invoked from the
  sibling `e203_hbirdv2` directory.
