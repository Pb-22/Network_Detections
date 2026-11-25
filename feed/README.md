# Pb-22 Open Suricata Feed

The Pb-22 Open Suricata Feed provides independently maintained rules for network threat detection and hunting. Packet captures, documentation and reproducible validation support the rules in the feed.

## Source and SID allocation

The source identifier is `pb-22/open`. [SID allocation PR #56](https://github.com/sidallocation/sidallocation.org/pull/56) merged on November 19, 2026, allocating `9955000–9959999` to Pb-22. The current feed uses `9955000–9955003` and `9955009–9955010`.

[OISF request #45](https://github.com/OISF/suricata-intel-index/issues/45) tracks review for the Suricata Rule Index. [The prepared index entry](submissions/oisf-index-entry.yaml) supplies the source metadata and an 8.0.8 compatibility baseline.

The feed contains independently published rules with unique SIDs and can be selected alongside ET Open.

## Subscription feed URL

https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules

The raw GitHub URL supplies the maintained rule file.

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
- zero alerts on the RedFlick control;
- four Sliver hunting alerts on the retained proof capture;
- one alert for each CAV3RN DNS branch;
- one WMI encoding alert on the authentic execution and seven on the combined capture in both `single` and `autofp` modes;
- one recovery inhibition alert on the combined action fixture in both `single` and `autofp` modes, zero on split actions and one on the documented control with a different interface;
- one separate WMI encoding alert on the recovery positive and different interface captures, which retain that request from the source conversation;
- clean rule loading with zero warnings or errors.

[Validation results](validation-results.json) record the exact feed digest, engine version, address groups and alert counts for each replay. Configure address groups for the monitored network when selecting the feed.

The [SID map](sid-map.csv) lists the current and previous IDs for all eleven repository rules. Replace each previous SID generation with its mapped current rule.

The aggregate selects the six rules in the table above. DCSync (`9955004`) and EarthWorm (`9955005–9955007`) have separate packages. EarthWorm uses the Lua scripts supplied with its package. BPFDoor (`9955008`) is commented out by default.

[WMI encoding](../WMI/) documents sixteen cases, including six intended positives and a matching control with a different interface. The combined capture produces seven alerts. [Recovery inhibition](../WMI/T1490-Inhibit-System-Recovery/Suricata/) documents sixteen positives, twenty four quiet negatives and a matching control with a different interface. The retained results show the matching boundaries for both rules.

## Source acquisition

[Acquisition results](acquisition-results.json) record an isolated source test with suricata-update 1.3.8 and Suricata 8.0.8. The updater fetched `pb-22/open` from the published URL and preserved all six feed signatures. Suricata loaded the merged file with six feed rules and 384 distribution rules, for 390 rules total. Rule loading completed with zero failures and zero skipped rules.

## Build

Run:

```text
python3 tools/build_suricata_feed.py
python3 tools/build_suricata_feed.py --check
sha256sum --check feed/SHA256SUMS
```

Edit `feed/source/pb22.rules` and run the builder to regenerate `feed/suricata/pb22.rules` and its checksums.

## Installation

Before OISF index acceptance, users can add the feed URL manually:

```text
suricata-update add-source pb-22/open https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules
suricata-update enable-source pb-22/open
suricata-update
```

Once OISF lists the source, select `pb-22/open` from the refreshed index:

```text
suricata-update update-sources
suricata-update enable-source pb-22/open
suricata-update
```

## License

The feed files under `feed/` use the [BSD-3-Clause license](LICENSE).
