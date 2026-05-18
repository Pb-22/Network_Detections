# Pygmy Goat / EarthWorm

This folder contains the pool-number follow-on to the broader EarthWorm detection work.

The main idea here is simple: move beyond matching the EarthWorm request-stage sequence alone and check whether the trailing 4-byte pool value seen in `01 04` is reused in `01 05`, then confirm the later SOCKS request stage.

## Reference

Primary protocol grounding:

- UK National Cyber Security Centre (NCSC), *Malware Analysis Report: Pygmy Goat*
- Relevant section: **pages 19-21**
- URL: <https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat.pdf>

## What is in this folder

- `Suricata_Rules_with_Supporting_Lua.md` , pool-aware Suricata detection notes, the validated rule set, and the two supporting Lua helpers
- `Zeek_Script.md` , a pool-aware Zeek detection path for the same behavior family
- `PCAPs/` , packet captures for the pool-number follow-on work
- `ncsc-mar-pygmy-goat(check_Pages_18-20)_compressed.pdf` , local reference copy

## Supporting project links

- Updated lab section: <https://github.com/Pb-22/EarthWorm-Lab/tree/main#reproducing-the-pool-number-pcap-family>
- Updated Suricata-Bench: <https://github.com/Pb-22/Suricata-Bench>
- Related article: <https://brimerica.com/articles/earthworm-pygmy-goat>

The article is useful if you want the path that led to the final Lua solution. It covers several things that were tried before settling on the working store-and-compare approach.

## Current validated Suricata direction

The working Suricata path is the split Lua-backed sequence:

1. store the trailing 4-byte pool value from `01 04`
2. compare it to the trailing 4-byte pool value from `01 05`
3. only then allow the `05 02 00 01` request-stage alert

This grew out of failed pure-rule equality attempts. The current approach keeps the stage logic in Suricata rules and uses Lua for the numeric state comparison.

## Validation shorthand

- `ew-test-08` -> alert
- `ew-test-09` -> alert
- `ew-test-10` -> no alert
- `ew-test-07` -> no alert

## Current pivot note

The next writing focus is the website path. When resuming, treat the website article and related public-facing explanation as the active thread, not more low-level lab redesign unless a new detection gap is found.
