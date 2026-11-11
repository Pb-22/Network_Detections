# Pb-22 Open Suricata Feed

Status: candidate before SID registration

This directory contains the independently maintained Pb-22 Suricata feed. The feed is built from reviewed rules in this repository and is intended to become an optional source in the OISF Suricata Rule Index.

## Important current boundary

The current SIDs `1000201` through `1000205` are temporary values in the community local use range. They are suitable for isolated validation, but they are not a public allocation. Do not deploy or redistribute this candidate feed until sidallocation.org assigns a permanent block and the feed is renumbered.

Rules that already belong to ET Open are intentionally excluded. Enabling this feed beside ET Open must not create duplicate ET SIDs.

## Candidate feed URL

After publication:

https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules

The GitHub URL is sufficient for the initial feed and SID request. A matching `brimerica.com` feed URL can be added later without changing the rule source of record.

## Included rules

| Temporary SID | Detection | Validation fixture | Observed alerts |
|---:|---|---|---:|
| 1000201 | RedFlick DNSObserver HTTP check-in | `RedFlick/pcap/redflick-dnsobserver-http.pcap` | 1 |
| 1000202 | Possible Sliver age and minisign material | `Sliver_Pivot-minisign_signature/scenario12_age_minisign.pcap` | 4 |
| 1000203 | CAV3RN DNS channel selection | `Cav3rn/pcap/Cav3rn.pcap` | 1 |
| 1000204 | CAV3RN DNS deployment ID freshness | `Cav3rn/pcap/Cav3rn.pcap` | 1 |
| 1000205 | CAV3RN DNS deployment ID recovery | `Cav3rn/pcap/Cav3rn.pcap` | 1 |

## Validation

The generated feed passed:

- deterministic build and checksum verification;
- Suricata 8.0.4 `-T` syntax validation;
- direct Suricata-Bench replay with all five rules enabled;
- one RedFlick alert and silence on its three negative controls;
- four Sliver hunting alerts on the retained proof capture;
- one alert for each CAV3RN DNS branch;
- no Suricata-Bench diagnostics.

Machine-readable results are in `validation-results.json`.

## Build

Run:

```text
python3 tools/build_suricata_feed.py
python3 tools/build_suricata_feed.py --check
sha256sum --check feed/SHA256SUMS
```

Edit `feed/source/pb22.rules`; do not hand-edit the generated `feed/suricata/pb22.rules`.

## Installation after SID registration

Before OISF index acceptance, users can add the permanent feed URL manually:

```text
suricata-update add-source pb22 https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules
suricata-update enable-source pb22
suricata-update
```

After OISF index acceptance, the intended source name is `pb22/open`:

```text
suricata-update update-sources
suricata-update enable-source pb22/open
suricata-update
```

## License

The feed files under `feed/` are licensed under BSD-3-Clause. This license does not claim ownership of third party reports or PDFs elsewhere in the repository.
