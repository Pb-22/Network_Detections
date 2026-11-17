# Network_Detections

This repository is a collection of network detections organized alongside test PCAPs that I created.

In most cases, the PCAPs are minimal but realistic enough to exercise the included detections and the behaviors or IoCs described in recent threat intelligence reporting.

Where useful, links to the original articles or local PDF copies may be included for reference. Those articles are not my work and, when included, are provided for informational purposes only.

If you want to test these detections yourself, you may find tools like **Suricata Bench** useful for Suricata rules and **zeek-try-cluster** useful for Zeek scripts.

Current EarthWorm-related directories:

- `Earthworm/` — base reverse-SOCKS handshake and request-stage detection material
- `Pygmy-Goat-Earthworm/` — pool-number follow-on with `ew-test-07` through `ew-test-10`

Additional detection packages:

- [`RedFlick/`](RedFlick/): published ET Open check in and User-Agent rules, synthetic PCAP, and visual explainer.
- [`DCSync/`](DCSync/): DRSUAPI replication detection, authentic lab captures, and packet walkthrough.
- [`WMI/`](WMI/): WMI command-output encoding rule, sixteen comparison cases, and a combined replay capture.
- [`Certipy/`](Certipy/): certificate authentication detection packages, including [PKINIT-U2U](Certipy/PKINIT-U2U/) with tested Zeek source, authentic captures and 39 offline replay cases.

## Pb-22 Open Suricata feed

The independent feed is documented under [`feed/`](feed/). It contains five fixture-backed rules, deterministic generation, checksums, Suricata 8 validation results, feed-specific BSD-3-Clause licensing, and SID allocation and OISF index submission material.

The downloadable feed uses SIDs `9955000-9955003` and WMI encoding SID `9955009` within the maintainer-authorized `9955000-9959999` range. The [repository-wide SID map](feed/sid-map.csv) also lists DCSync and the Lua-backed EarthWorm rules in their individual directories, plus disabled-by-default BPFDoor SID `9955008`. These additional rules are not automatically included in the aggregate feed. RedFlick is supplied by ET Open and is excluded from this independent feed. Registry PR review and OISF index listing are separate from permission to use the range.

Subscription feed URL:

https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules
