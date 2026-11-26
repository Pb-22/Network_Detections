# iodine test captures

Start with [iodine-dns-positive-complete-session.pcap](pcap/iodine-dns-positive-complete-session.pcap). It contains a complete observed iodine DNS tunnel session: version negotiation, login, and tunnel data in both directions. The tested session recognizer produces one `Iodine::CompatibleSession` Notice.

This directory contains five selected captures, their expected results, and checksums. The set covers DNS transport, Raw UDP transport, DNS fragmentation, and two controls that stop short of the required session evidence.

## Files and expected results

| Capture | Test | Origin | Packets | Expected Notices |
| --- | --- | --- | ---: | ---: |
| [iodine-dns-positive-complete-session.pcap](pcap/iodine-dns-positive-complete-session.pcap) | Main test: complete DNS session, with NULL replies, Base128 upstream and Raw downstream | Native | 66 | 1 |
| [iodine-raw-udp-positive-complete-session.pcap](pcap/iodine-raw-udp-positive-complete-session.pcap) | DNS negotiation followed by a complete Raw UDP session | Native | 33 | 1 |
| [iodine-dns-positive-fragmented-session.pcap](pcap/iodine-dns-positive-fragmented-session.pcap) | Complete DNS session with seven upstream and five downstream fragments | Native | 57 | 1 |
| [iodine-dns-negative-negotiation-only.pcap](pcap/iodine-dns-negative-negotiation-only.pcap) | Version and login negotiation, with no tunnel data | Derived control | 6 | 0 |
| [iodine-dns-negative-upstream-data-only.pcap](pcap/iodine-dns-negative-upstream-data-only.pcap) | Negotiation and upstream data, with downstream data bodies removed | Derived control | 55 | 0 |

Counts refer specifically to `Iodine::CompatibleSession`, using the detector source hashes recorded in [validation.json](validation.json). The five files produced the expected results in Zeek 9.0.1, with successful engine exits and empty engine stderr. Packet counts include every captured frame. The captures contain no truncated frames.

The control with upstream data retains downstream ACK headers and DNS replies. It tests the requirement for tunnel data in both directions, rather than simply removing all server packets. The negotiation control shows why a version exchange and successful login alone are insufficient for this Notice.

## Review the traffic in Wireshark

Open the main DNS capture and apply:

```text
udp.port == 53
```

The baseline has 55 packets on UDP/53. To focus on its NULL record exchanges, use:

```text
dns.qry.type == 10
```

The Raw UDP capture begins with DNS negotiation and then carries iodine Raw UDP packets on port 53. To select its 12 Raw UDP packets, use:

```text
udp.payload[0:3] == 10:d1:9e
```

The default DNS dissector labels these Raw UDP packets as malformed DNS because they use port 53. Inspect their UDP payload, or use **Decode As → Data** for that traffic. The `10 d1 9e` header identifies the Raw transport in this capture; the session recognizer also requires the preceding negotiation and two way data evidence.

The baseline client and server are `10.205.0.3` and `10.205.0.2`, using the lab suffix `iodine-lab.test`. The fragmented session uses `10.207.0.3`, `10.207.0.2`, and `p14-tunnel.test`.

## Replay with the session recognizer

Use Zeek 9.0.1 and the iodine session recognizer that emits `Iodine::CompatibleSession`. Its runtime consists of `main.zeek`, `state.zeek`, and `wire.zeek`; keep those files together. This capture directory supplies the test inputs and recorded results. The detector is a separate prerequisite, and its exact source hashes are in [validation.json](validation.json).

From the root of this repository, set `SCRIPT` to the absolute path of the detector entry point:

```sh
CAPTURE="$PWD/iodine/pcap/iodine-dns-positive-complete-session.pcap"
SCRIPT="/absolute/path/to/iodine/scripts/main.zeek"
mkdir -p iodine-replay/dns-positive
cd iodine-replay/dns-positive
zeek -C -r "$CAPTURE" "$SCRIPT"
```

Run each capture in a separate output directory so that logs remain tied to one test. `-C` matches the replay's treatment of checksum offload in the native captures.

For the main test, `notice.log` should contain one entry with:

```text
note: Iodine::CompatibleSession
msg: iodine session pattern observed: matched negotiation followed by two way tunnel traffic
```

Its `sub` field should report:

```text
evidence=version,login,data_up,data_down
transport=dns
suffix=iodine-lab.test
userid=0
upstream=Base128
downstream=Raw
```

These are individual values from the semicolon separated `sub` field. The Raw UDP test reports `transport=raw`, `upstream=Raw`, and `downstream=Raw`. The fragmented test reports `up_fragments=7` and `down_fragments=5`.

Each negative control should produce zero `Iodine::CompatibleSession` entries. Zeek can omit `notice.log` when a run emits no Notices; confirm that the process completed successfully before interpreting an absent file as a measured zero.

## Provenance and verification

The three native captures came from real iodine sessions in a controlled lab using harmless ping or UDP echo traffic. The source reference is iodine commit [`7160bbe1c98c74bf34a8b97ed8c1540950ebb243`](https://github.com/yarrick/iodine/tree/7160bbe1c98c74bf34a8b97ed8c1540950ebb243). The two derived controls were constructed from the main DNS capture with the changes described above. Original capture bytes and control bytes are preserved under descriptive filenames.

[validation.json](validation.json) records each file's origin, packet count, SHA256, expected and observed Notice counts, engine result, and detector source hashes. Positive results were also checked against captured negotiation, complete body and fragment evidence, and the time at which that evidence became available.

To verify the published files from this directory:

```sh
sha256sum --check SHA256SUMS
```

The captures demonstrate iodine compatible session behavior in this test set. The Notice describes observed protocol evidence; authorized iodine use can produce the same result.
