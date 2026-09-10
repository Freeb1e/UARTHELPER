# Change Log

## 2026-09-10 - Three-parameter board regression

- Generated keygen_commands_128.txt, keygen_commands_192.txt and refreshed
  keygen_commands_256.txt from official KAT seeds, 10 commands each.
- Ran all three parameter sets sequentially on the same v3 firmware through
  ttyUSB2: 30/30 complete PK/SK comparisons passed. Mean total cycles were
  1058414 / 2692844 / 4679940.8 for 128/192/256 respectively.
- Archived stage logs in e203_hbirdv2/docs/data/scloud{128,192,256}_uart_all_20260910.txt
  and documented the all-parameter test command and performance results.

## 2026-09-10 - Board validation

- Ran all 10 canonical 256-SM3 vectors on /dev/ttyUSB2 after verified ILM
  loading of protocol-v3 firmware; every full PK/SK comparison passed.
- Mean total: 4679940.8 cycles. Archived all stage readings in
  e203_hbirdv2/docs/data/scloud256_uart_20260910.txt and updated the board
  performance report with time conversions at startup-measured 20004536 Hz.

## 2026-09-10 - Host random-input generation

- Generate z and alpha on the host with the official api_pkc/drng.c, using
  separate 64-byte draws in reference KEM/PKE order. Requires host compiler cc.
- Send protocol-v3 `KEYGEN <parameter> <z||alpha_hex>` commands and support
  `--commands-out` export with no serial connection. Generated the 10 canonical
  256-SM3 commands in keygen_commands_256.txt. Seed-only protocol removed.
- All 10 tests passed, including z/SK and F(alpha)/PK seedA checks for all
  30 KAT records across 128/192/256-SM3 and command-only export. Board firmware
  rebuilt and passed image checks; no board PK/SK run.

## 2026-09-10

- Display all board stage counters before each PK/SK comparison result,
  including separate column compaction and Pack10 counters in the debug image.
- Added optional `--cpu-mhz` for conversion to milliseconds using the actual
  board CPU frequency; DRNG is explicitly marked as excluded from the total.
- Validation: all 8 tests passed, covering stage display, time conversion,
  cycle-only output and invalid frequency rejection. No board run.
- Updated the default KeyGen KAT path to the merged repository's
  `third_party/Scloud+/Test_Vectors` directory.
- Updated UART test commands and documented explicit vector paths relative to
  the working directory.
- Validation: all 5 parser/protocol tests passed; all 10 records in each of the
  128/192/256-SM3 KAT files loaded successfully. Default loading also passed from
  both the repository root and `UARTHELPER`. Board testing was not performed
  because no `/dev/ttyUSB*` device was available.

## 2026-08-28

- Added direct parsing of canonical Scloud+ packed10 KAT files.
- Added sequential UART KeyGen execution that sends only each record's
  parameter and 64-byte Seed, then compares the returned complete PK/SK pair.
- The request format is `KEYGEN <parameter> <seed_hex>` and works with one
  unified 128/192/256-SM3 board image.
- Added protocol/parser unit tests and documented the supported production
  hardware instances: 128-SM3, 192-SM3, and 256-SM3.
- Clarified the test commands for invocation from either the project root or
  the `UARTHELPER` directory.
