# Network_Detections

This repository is a collection of network detections organized alongside test PCAPs that I created.

In most cases, the PCAPs are minimal but realistic enough to exercise the included detections and the behaviors or IoCs described in recent threat intelligence reporting.

Where useful, links to the original articles or local PDF copies may be included for reference. Those articles are not my work and, when included, are provided for informational purposes only.

If you want to test these detections yourself, you may find tools like **Suricata Bench** useful for Suricata rules and **zeek-try-cluster** useful for Zeek scripts.

Current EarthWorm-related directories:

- `Earthworm/` — base reverse-SOCKS handshake and request-stage detection material
- `Pygmy-Goat-Earthworm/` — pool-number follow-on with `ew-test-07` through `ew-test-10`

Additional detection packages:

- [`RedFlick/`](RedFlick/) — DNSObserver HTTP C2 check in rule, synthetic PCAP, and visual explainer

## Pb-22 Open Suricata feed

The independent feed candidate is documented under [`feed/`](feed/). It currently contains five fixture backed rules, deterministic generation, checksums, Suricata 8 validation results, feed specific BSD-3-Clause licensing, and prepared SID allocation and OISF index submission material.

The current `1000201-1000205` SIDs are temporary local use values. Do not deploy the candidate as a public source until sidallocation.org assigns the permanent block and the feed is renumbered.

Candidate feed URL:

https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules
