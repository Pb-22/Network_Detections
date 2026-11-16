# RedFlick DNSObserver Test Capture

[redflick-dnsobserver-http.pcap](redflick-dnsobserver-http.pcap) contains four synthetic HTTP exchanges derived from the documented DNSObserver request shape. It uses documentation addresses and contains 40 Ethernet, IPv4, and TCP packets.

## Requests and observed results

| Packet range | Request frame | Case | SID 2072753 | SID 2072754 |
| --- | ---: | --- | ---: | ---: |
| 1 to 10 | 4 | Full request pattern | 1 | 1 |
| 11 to 20 | 14 | User-Agent changed to `WindowsUpdateClient/10.0` | 0 | 0 |
| 21 to 30 | 24 | Path changed to `/dns/status?ui=...` | 0 | 1 |
| 31 to 40 | 34 | Value changed to `ui=short` | 0 | 1 |

Suricata 8.0.8 replay loaded the exact [published ET rules](../Suricata/redflick-dnsobserver.rules), with `192.0.2.10` included in `$HOME_NET` and `198.51.100.20` included in `$EXTERNAL_NET`.

The path and value length cases are negative controls for the full check in signature. They remain positive for the broader User-Agent signature by design.

Use the Wireshark display filter `http.request` to compare all four requests. TShark verified the intended fields, packet count, and absence of malformed or truncated frames.

## Explainers

- [PNG visual explainer](redflick-explainer.png)
- [Browser explainer source](redflick-explainer.xml)

These explainers show the observed results for both published ET signatures. Package hashes are in [SHA256SUMS](../SHA256SUMS).
