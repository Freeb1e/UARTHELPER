# Scloud+ Reference Vectors And Legacy UART Tools

The former UART firmware and automatic image-loading runner have been removed.
Retained host protocol tools and vectors are documented in
[SCLOUDKEYGEN](../SCLOUDKEYGEN/README.md),
[SCLOUDENCAPS](../SCLOUDENCAPS/README.md), and
[SCLOUDDECAPS](../SCLOUDDECAPS/README.md). Sending their commands requires a
separately supplied compatible UART device; vector preparation is independent
of that device.

Current [PQC-PACE-Scloud firmware](../../e203_hbirdv2/scripts/PQC-PACE-Scloud/README.md)
supports parameter sets 128/192/256 through DTCM simulation inputs and does not
implement these UART commands. The retained parameter-512 reference vectors
do not imply parameter-512 support in current PACE firmware.
