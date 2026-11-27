# dnscat2 DNS session captures

[Download the primary TXT PCAP](pcap/dnscat2-txt-positive-complete-session.pcap). It produces **one `DNScat2::CompatibleSession` Notice** with the maintained detector on Zeek 9.0.1.

The ready captures are the first testing option. Each file is an endpoint anonymized derivative of accepted native lab traffic. The negative also retains its original mutation of reply session IDs.

## Replay the primary capture

Use the [maintained detector source](https://github.com/Pb-22/zeek-detections/blob/36171b8a3ac997a726969da15e655253f0d82fff/scripts/dnscat2/main.zeek) from `Pb-22/zeek-detections`. From that repository root, with the downloaded capture in the current directory:

```sh
zeek -C -r dnscat2-txt-positive-complete-session.pcap scripts/dnscat2/main.zeek
```

Inspect `notice.log` for one `DNScat2::CompatibleSession` record. The `-C` option matches the validated replay command. Each capture runs independently with `main.zeek`. The [optional finite adapter](https://github.com/Pb-22/zeek-detections/blob/36171b8a3ac997a726969da15e655253f0d82fff/scripts/dnscat2/cluster.zeek) uses explicit assigned inputs and node configuration; ordinary single capture replay uses main directly.

## Capture results

| Ready PCAP | Origin | Frames | Expected Notices | Observed Notices |
| --- | --- | ---: | ---: | ---: |
| [TXT complete session](pcap/dnscat2-txt-positive-complete-session.pcap) | Derived from native lab session | 27 | 1 | 1 |
| [CNAME complete session](pcap/dnscat2-cname-positive-complete-session.pcap) | Derived from native lab session | 26 | 1 | 1 |
| [MX complete session](pcap/dnscat2-mx-positive-complete-session.pcap) | Derived from native lab session | 26 | 1 | 1 |
| [A complete session](pcap/dnscat2-a-positive-complete-session.pcap) | Derived from native lab session | 29 | 1 | 1 |
| [AAAA complete session](pcap/dnscat2-aaaa-positive-complete-session.pcap) | Derived from native lab session | 29 | 1 | 1 |
| [Inconsistent reply session IDs](pcap/dnscat2-negative-inconsistent-reply-session-ids.pcap) | Derived negative with endpoint anonymization | 14 | 0 | 0 |

The negative preserves its earlier constructed mutation of native DNS bytes: reply session IDs disagree with the retained session. Its zero Notice result exercises session correlation with complete outer DNS messages.

All six actual replays used the detector source above and the pinned Zeek 9.0.1 image recorded in [validation.json](pcap/validation.json). Every engine exited zero with empty stderr. The detector writes aggregate health counters to stdout. Positive Notices describe paired negotiation and session start followed by traffic in both directions.

## Provenance and transformations

Original producers used upstream dnscat2 v0.07 at revision `42f8d783488836c0e24ff25571684170be0a0cc2`, with encryption enabled and a controlled lab roundtrip. The existing accepted inputs supplied these derivatives; endpoint anonymization required only offline packet processing.

IPv4 client and server endpoints become `192.0.2.10` and `198.51.100.20`, from RFC 5737 documentation ranges. Other endpoint fields use documentation addresses. IPv6 unicast endpoints use RFC 3849 `2001:db8::/32`. Ethernet addresses become locally administered values. Matching ARP endpoint fields, IPv6 control address fields and neighbor discovery link layer options follow consistent maps. Address derived solicited node membership groups follow the mapped IPv6 endpoints. Protocol multicast and unspecified addresses retain their protocol roles.

IPv4 header, UDP and ICMPv6 checksums were recomputed and independently verified. The transformation preserves the complete frame sequence, timestamps, lengths, flow directions, ports and DNS transaction IDs. Full DNS payload bytes remain exact, including query names, public negotiation keys, encrypted tunnel bytes and the A and AAAA records carrying protocol cells. ARP and IPv6 background frames remain present.

Payloads retain the encrypted bytes of controlled native lab roundtrips. Endpoint and marker reviews describe observable packet fields; application encryption remains intact. The origin label for every public file is **derived from native lab traffic after endpoint anonymization**.

[manifest.json](pcap/manifest.json) records input hashes, derivative hashes, origins and transformations. [validation.json](pcap/validation.json) records actual source bound replay results and preservation checks. [SHA256SUMS](pcap/SHA256SUMS) verifies the ready captures and metadata.

## Further inspection

Open any ready PCAP directly in Wireshark. Use `dns` for protocol messages, `arp` for retained address resolution, or `icmpv6` for retained IPv6 control traffic. The TXT file is the primary example; other files exercise the corresponding DNS reply carriers. Reproduction and finite topology work are optional followups to these ready inputs.
