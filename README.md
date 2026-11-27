# Network_Detections

This repository is a collection of network detections organized alongside test PCAPs that I created.

In most cases, the PCAPs are minimal but realistic enough to exercise the included detections and the behaviors or IoCs described in recent threat intelligence reporting.

Where useful, links to the original articles or local PDF copies may be included for reference. Those articles are not my work and, when included, are provided for informational purposes only.

If you want to test these detections yourself, you may find tools like **Suricata Bench** useful for Suricata rules and **zeek-try-cluster** useful for Zeek scripts.

EarthWorm directories:

- `Earthworm/`: detection material for reverse SOCKS handshakes and requests.
- `Pygmy-Goat-Earthworm/`: followup detection for the pool number, with `ew-test-07` through `ew-test-10`.

Additional detection packages:

- [`RedFlick/`](RedFlick/): published ET Open check in and User-Agent rules, synthetic PCAP, and visual explainer.
- [`DCSync/`](DCSync/): DRSUAPI replication detection, authentic lab captures, and packet walkthrough.
- [`WMI/`](WMI/): rules for encoded WMI command output and combined recovery inhibition, positive and negative captures, and replay results.
- [`Certipy/`](Certipy/): certificate authentication packet evidence, including [PKINIT-U2U](Certipy/PKINIT-U2U/). Its maintained detector and replay suite are in [Pb-22/zeek-detections](https://github.com/Pb-22/zeek-detections).
- [`iodine/`](iodine/): native DNS and Raw UDP tunnel captures, a fragmentation test, and two negative controls with expected Zeek Notice results.
- [`pe-disguise/`](pe-disguise/): a Zeek detector for PE files advertised as documents or images, with ready test PCAPs and scripts to reproduce and replay them.

## Pb-22 Open Suricata feed

The independent feed is documented under [`feed/`](feed/). It contains six rules with test fixtures, deterministic generation, checksums, Suricata 8 validation results, a BSD-3-Clause license for the feed, and SID allocation and OISF index submission material.

The downloadable feed uses SIDs `9955000-9955003` and WMI SIDs `9955009-9955010` within the `9955000-9959999` range authorized by the maintainer. The [repository SID map](feed/sid-map.csv) also lists DCSync and the EarthWorm rules that use Lua in their individual directories, plus BPFDoor SID `9955008`, which is disabled by default. These additional rules are not automatically included in the aggregate feed. ET Open supplies RedFlick, so this independent feed excludes it. Registry PR review and OISF index listing are separate from permission to use the range.

Subscription feed URL:

https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules
