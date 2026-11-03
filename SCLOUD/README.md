# Scloud+ Reference Vectors And UART Tools

Host protocol tools and vectors are documented in
[SCLOUDKEYGEN](../SCLOUDKEYGEN/README.md),
[SCLOUDENCAPS](../SCLOUDENCAPS/README.md), and
[SCLOUDDECAPS](../SCLOUDDECAPS/README.md). Load the operation and parameter's
[HWDISPLAY UART image](../../e203_hbirdv2/scripts/HWDISPLAY/README.md) before
using the board clients; they do not upload firmware automatically.
[SIMDISPLAY](../../e203_hbirdv2/scripts/SIMDISPLAY/README.md) uses the same
commands and response format in E203 SoC simulation.

Both display variants use the current
[PQC-PACE-Scloud core](../../e203_hbirdv2/scripts/PQC-PACE-Scloud/README.md)
for parameter sets 128/192/256. Parameter-512 vectors remain reference data
and require a separately supplied compatible device for UART execution.
