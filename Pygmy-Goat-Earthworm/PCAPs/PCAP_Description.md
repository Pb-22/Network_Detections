# PCAP Files
- ew-test-07-pool-disabled-zero.pcap
- ew-test-08-pool-enabled-04d2.pcap
- ew-test-09-pool-enabled-1337.pcap
- ew-test-10-pool-mismatch-04d2-1337.pcap

## Description
- ew-test-07 : Zero-pool baseline. `01 03`, `01 04`, and `01 05` all carry `00 00 00 00`.
- ew-test-08 : Matched pool sample using `0x000004d2` across `01 03`, `01 04`, and `01 05`.
- ew-test-09 : Matched pool sample using `0x00001337` across `01 03`, `01 04`, and `01 05`.
- ew-test-10 : Negative-control mismatch sample. `01 03` and `01 04` use `0x000004d2`, while `01 05` uses `0x00001337`.

## Detection expectation
- ew-test-08 and ew-test-09 should alert on the validated Lua-backed pool-aware path.
- ew-test-10 should not alert on that path.
- ew-test-07 is intentionally useful as the zero-pool baseline and does not alert on the current non-zero pool-aware rules.
