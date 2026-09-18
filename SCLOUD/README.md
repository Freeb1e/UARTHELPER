# HWDISPLAY Scloud+ board smoke tests

`run_hwdisplay_tests.py` loads and verifies one parameter-specific HWDISPLAY
image over JTAG, then checks official SM3 packed10 KAT Count=0 against complete
board outputs. Decaps also checks a tampered Count=0 ciphertext and its
independently calculated rejection secret. Valid requests are read from the
pre-generated first UART commands in `SCLOUD{KEYGEN,ENCAPS,DECAPS}`. Those
commands were derived from Count=0 KAT on the host; the test runner does not
run DRNG for valid requests and the board never runs DRNG. The existing
`SCLOUD*` parsers check complete responses, and the Decaps helper constructs
the additional tampered-ciphertext request on the host.

Run from the repository root after loading a matching FPGA bitstream and
building the target image:

```sh
make -C e203_hbirdv2/scripts/HWDISPLAY/scloud_encaps check-image SCLOUD_PARAMETER=128
.venv/bin/python -u UARTHELPER/SCLOUD/run_hwdisplay_tests.py \
    --operation encaps --parameter 128 --port /dev/ttyUSB2 \
    --results /tmp/hwdisplay-scloud-encaps-128
```

Use a new result directory for each run. Choose `128`, `192`, `256` or `512`;
parameter 512 builds from the separate `scloud512_<operation>` directory.
`results.json` records firmware, KAT and command-file identities, checked outputs and cycles.
`transcript.txt` contains the full UART TX/RX and OpenOCD load/verify output.
This single-case check does not replace the existing ten-record KAT suites.
