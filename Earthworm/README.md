# EarthWorm packet tests

Start with [the single HTTP session](PCAPs/ew-test-01-handshake-single-http.pcap).
It is a ready public test capture. The current Zeek detector produces two
Notices: one for setup and one for the request sequence after setup.

Open the PCAP in Wireshark, or save the Zeek code block from
[Zeek_Script.md](Zeek_Script.md) as earthworm.zeek and replay it with stock
Zeek 9.0.1:

```sh
zeek -C -r ew-test-01-handshake-single-http.pcap earthworm.zeek
```

Run in a separate output directory and inspect notice.log. The source reader
also provides the extracted Zeek source, so a consumer does not need to run a
Python extraction or generation script.

## Current replay results

All six existing PCAP files were replayed against the same extracted detector
source. Counts include both EarthWorm Notice types.

| PCAP | Setup Notices | Request Notices | Total |
|---|---:|---:|---:|
| [Single HTTP session](PCAPs/ew-test-01-handshake-single-http.pcap) | 1 | 1 | 2 |
| [Repeated setup and requests](PCAPs/ew-test-02-handshake-double-http.pcap) | 1 | 3 | 4 |
| [Tunnel activity](PCAPs/ew-test-03-tunnel-activity-single-http.pcap) | 0 | 1 | 1 |
| [Reconnect setup](PCAPs/ew-test-04-reconnect-handshake.pcap) | 1 | 0 | 1 |
| [Delayed HTTP setup](PCAPs/ew-test-05-handshake-delayed-http.pcap) | 1 | 1 | 2 |
| [Several tunnel requests](PCAPs/ew-test-06-tunnel-activity-multi-http.pcap) | 0 | 3 | 3 |

These are the existing published test captures, retained without rewriting
packet bytes. They exercise the source patterns; a match is not proof of a
particular operator or an authentic malware execution. The
[packet descriptions](PCAPs/PCAP_Description.md) explain the scenarios.

The [reader notes](../website-notes/Earthworm/Zeek_Script.json) accompany the
extracted source and explain each detection step at its matching source range.
