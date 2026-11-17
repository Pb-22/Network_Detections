# WMI Encoding Test Captures

These captures exercise the command-output encoding rule against an observed WMI execution, encrypted and read-only controls, TCP segmentation variants, and constructed request boundaries. The sixteen separate files retain their original bytes. The combined file assembles all cases into isolated replay windows.

## Files and results

[Download the combined capture](wmi-command-output-encoding-combined.pcap). It contains 11,055 packets: 10,975 source packets and 80 added zero-payload TCP reset packets. Results below use Suricata 8.0.8 and [SID 9955009](../Suricata/wmi-command-output-encoding.rules).

P means the encoding rule should alert. N means it should remain quiet. Packet counts refer to the separate files; combined ranges include each case's added reset packets.

| Test | Type | Separate capture | Packets | Combined frames | Observed alerts |
| --- | --- | --- | ---: | --- | ---: |
| Authentic execution | P | [authentic-execution.pcap](separate/authentic-execution.pcap) | 202 | 1–208 | 1 |
| Native encrypted control | N | [native-sealed-control.pcap](separate/native-sealed-control.pcap) | 122 | 209–335 | 0 |
| Visible read-only WMI query | N | [same-client-readonly.pcap](separate/same-client-readonly.pcap) | 115 | 336–456 | 0 |
| Prefix before encoding is visible | N | [command-only-excerpt.pcap](separate/command-only-excerpt.pcap) | 111 | 457–573 | 0 |
| 512-byte TCP segments | P | [segmented-512.pcap](separate/segmented-512.pcap) | 366 | 574–945 | 1 |
| 96-byte TCP segments | P | [segmented-96.pcap](separate/segmented-96.pcap) | 1443 | 946–2394 | 1 |
| 17-byte TCP segments | P | [segmented-17.pcap](separate/segmented-17.pcap) | 7389 | 2395–9789 | 1 |
| Wrong RPC interface | N | [wrong-interface.pcap](separate/wrong-interface.pcap) | 202 | 9790–9997 | 1 |
| Wrong operation number | N | [wrong-opnum.pcap](separate/wrong-opnum.pcap) | 202 | 9998–10205 | 0 |
| Wrong class | N | [wrong-class.pcap](separate/wrong-class.pcap) | 202 | 10206–10413 | 0 |
| Wrong method | N | [wrong-method.pcap](separate/wrong-method.pcap) | 202 | 10414–10621 | 0 |
| Wrong encoding mode | N | [wrong-encoding.pcap](separate/wrong-encoding.pcap) | 202 | 10622–10829 | 0 |
| Case variation | P | [case-variation.pcap](separate/case-variation.pcap) | 202 | 10830–11037 | 1 |
| Coalesced matching requests | P | [coalesced-real-requests.pcap](separate/coalesced-real-requests.pcap) | 5 | 11038–11043 | 1 |
| Evidence split across requests | N | [coalesced-cross-request.pcap](separate/coalesced-cross-request.pcap) | 5 | 11044–11049 | 0 |
| Commented-out encoder command | N | [commented-encoder.pcap](separate/commented-encoder.pcap) | 5 | 11050–11055 | 0 |

The six positives each produce one alert. The wrong-interface negative also alerts, giving a combined total of seven. All other negatives remain quiet.

## Capture construction

The authentic execution, native encrypted comparison, and read-only query are controlled lab captures. The prefix case preserves the beginning of the authentic execution and ends before the encoder command value becomes visible. Its last portion already includes the opening segment of the encoding request.

The segmentation variants preserve TCP-direction payload bytes while splitting packets into smaller segments. Interface, operation, class, method, mode, and case variants alter their named fields. Coalesced cases combine observed request data to exercise matching and cross-request association. The commented-command case retains the encoder text inside a shell comment.

Constructed variants retain original RPC authentication fields while altering the test bytes. Their role is to exercise matching boundaries. The encrypted control is a visibility comparison: its command arguments are sealed.

The combined capture gives each case distinct private IP addresses and TCP connections, preserves original intra-case packet order and timing, and separates cases by fifteen seconds. IPv4, TCP, and UDP checksums are recomputed. Application bytes and embedded protocol addresses remain unchanged. Empty RST/ACK packets end each case's connections so later capture time does not change stream flushing or source-threshold behavior.

## Packet review

[cases.json](cases.json) records provenance, hashes, expected and observed outcomes, combined frame ranges, and combined flow endpoints.

Useful Wireshark display filters:

```text
dcerpc
```

```text
dcerpc.pkt_type == 0 && dcerpc.opnum == 24
```

```text
frame.number >= 1 && frame.number <= 208
```

The final example selects the authentic execution window in the combined capture. To inspect another case, use its frame range from the table. The encoding rule reads the TCP stream directly; protocol dissection is a separate view of the same packets.

## Integrity

Capture hashes are in [SHA256SUMS](../SHA256SUMS). Exact replay results are in [validation.json](../Suricata/validation.json).
