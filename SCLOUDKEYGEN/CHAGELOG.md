# Change Log

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
