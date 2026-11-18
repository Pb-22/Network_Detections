# Pb-22 Open Suricata Feed

Status: maintainer-authorized SID range; registry merge and OISF index listing pending

This directory contains the independently maintained Pb-22 Suricata feed. The feed is built from reviewed rules in this repository and is intended to become an optional source in the OISF Suricata Rule Index.

## Important current boundary

This feed uses SIDs `9955000-9955003` and WMI SIDs `9955009-9955010` within `9955000-9959999`. The registry maintainer [authorized use of the range](https://github.com/sidallocation/sidallocation.org/issues/55#issuecomment-6959202111) while [PR #56](https://github.com/sidallocation/sidallocation.org/pull/56) completes review. The OISF index entry is not yet accepted.

Rules that already belong to ET Open are intentionally excluded. Enabling this feed beside ET Open must not create duplicate ET SIDs.

## Subscription feed URL

https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules

The GitHub URL is sufficient for the initial feed and SID request. A matching `brimerica.com` feed URL can be added later without changing the rule source of record.

## Included rules

| SID | Detection | Validation fixture | Observed alerts |
|---:|---|---|---:|
| 9955000 | Possible Sliver age and minisign material | `Sliver_Pivot-minisign_signature/scenario12_age_minisign.pcap` | 4 |
| 9955001 | CAV3RN DNS channel selection | `Cav3rn/pcap/Cav3rn.pcap` | 1 |
| 9955002 | CAV3RN DNS deployment ID freshness | `Cav3rn/pcap/Cav3rn.pcap` | 1 |
| 9955003 | CAV3RN DNS deployment ID recovery | `Cav3rn/pcap/Cav3rn.pcap` | 1 |
| 9955009 | WMI-style certutil command-output encoding | `WMI/pcap/separate/authentic-execution.pcap` | 1 |
| 9955010 | WMI-style combined recovery-inhibition command | `WMI/T1490-Inhibit-System-Recovery/pcaps/combined-vss-bcd.pcap` | 1 |

## Validation

The generated feed passed:

- deterministic build and checksum verification;
- Suricata 8.0.8 `-T` syntax validation;
- offline file replay with all six rules enabled;
- zero alerts on the RedFlick fixture, confirming its ET-published rule is excluded;
- four Sliver hunting alerts on the retained proof capture;
- one alert for each CAV3RN DNS branch;
- one WMI encoding alert on the authentic execution and seven on the combined capture in both `single` and `autofp` modes;
- one recovery-inhibition alert on the combined-action fixture in both `single` and `autofp` modes, zero on split actions, and one on the documented wrong-interface control;
- one separate WMI encoding alert on the recovery-positive and wrong-interface captures, which retain that request from the source conversation;
- no rule-loading warnings or errors.

Machine-readable results are in `validation-results.json`. Replay address overrides are recorded there; use the monitored network's own address groups for deployment.

The [repository-wide SID map](sid-map.csv) lists all eleven independent rules and their previous IDs. Replace old local copies rather than loading both SID generations.

The map also distinguishes aggregate-feed membership: DCSync (`9955004`) and the Lua-backed EarthWorm group (`9955005-9955007`) remain in their individual directories, not in this six-rule aggregate. BPFDoor (`9955008`) remains commented out and disabled by default. WMI encoding (`9955009`) is included in the aggregate and documented in [its own package](../WMI/). Its sixteen-case table records six intended positives and one matching wrong-interface negative; the combined capture therefore produces seven alerts. Recovery inhibition (`9955010`) is included in the aggregate and documented in [its complete rule file](../WMI/T1490-Inhibit-System-Recovery/Suricata/). Its forty-one-case table preserves sixteen positives, twenty-four quiet negatives, and the matching wrong-interface negative. Lua-backed rules require the supporting scripts described in their package. Publishing this feed does not deploy it to a sensor or change its OISF index status.

## Build

Run:

```text
python3 tools/build_suricata_feed.py
python3 tools/build_suricata_feed.py --check
sha256sum --check feed/SHA256SUMS
```

Edit `feed/source/pb22.rules`; do not hand-edit the generated `feed/suricata/pb22.rules`.

## Installation

Before OISF index acceptance, users can add the feed URL manually:

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
