# Change Log

## 2026-09-13

- Added independent 640/976/1344 command files with 206/106/106 requests and
  line-aligned SS/failure-mask references plus original-source case indexes.
- Added a standalone entry point using the shared full-output validator and
  JTAG loader. --line selects a command and both corresponding references.
- Stage files pass round-trip validation; shared host tests pass. Full board
  batch results are recorded in evidence/frodo_board_20260913/full_run01.
