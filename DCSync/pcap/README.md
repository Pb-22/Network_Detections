# DCSync Test Captures

These captures pair a successful `DsGetNCChanges` exchange with a control that binds the same DRSUAPI interface and calls other operations. All three files preserve authentic traffic from a controlled lab exercise.

## Files and results

| File | Contents | Packets | Observed alerts |
| --- | --- | ---: | ---: |
| [negative-drsuapi-cracknames.pcap](negative-drsuapi-cracknames.pcap) | DRSUAPI operations 0, 16, and 12 | 48 | 0 |
| [positive-drsuapi-dsgetncchanges.pcap](positive-drsuapi-dsgetncchanges.pcap) | DRSUAPI operations 0, 16, and 3, with a successful replication response | 52 | 1 |
| [dcsync-positive-negative-combined.pcap](dcsync-positive-negative-combined.pcap) | Negative exchange followed by positive exchange | 100 | 1 |

Results use Suricata 8.0.8 and [SID 9955004](../Suricata/dcsync-dsgetncchanges.rules), with `10.77.10.10` included in `$HOME_NET`.

## Traffic profile

| Field | Value |
| --- | --- |
| Client | `10.77.12.10` |
| Directory server | `10.77.10.10` |
| Endpoint mapper | TCP/135 |
| DRSUAPI endpoint in these captures | TCP/49683 |
| DRSUAPI interface | `e3514235-4b06-11d1-ab04-00c04fc2dcd2` |
| Target operation | `3`, `IDL_DRSGetNCChanges` |

TCP/49683 is the endpoint selected in this exercise. The rule accepts any destination port so that it follows the parsed protocol rather than one captured port number. SMB authentication also appears in the captures; the DRSUAPI requests themselves use direct TCP RPC.

## Reviewing the combined capture

| Frame or range | Observation |
| --- | --- |
| 1 to 48 | Negative exchange |
| 19 | Endpoint mapper operation 3 |
| 28 | DRSUAPI interface bind |
| 33, 35, 37 | DRSUAPI operations 0, 16, and 12 |
| 49 to 100 | Positive exchange |
| 67 | Endpoint mapper operation 3 |
| 76 | DRSUAPI interface bind |
| 81, 83, 85 | DRSUAPI operations 0, 16, and 3 |
| 89 and 90 | Response fragments for the replication call |

Both exchanges include endpoint mapper operation 3. The negative control demonstrates why the detector must require the DRSUAPI interface UUID as well as operation 3.

Useful Wireshark display filters:

```text
dcerpc
```

```text
dcerpc.pkt_type == 0 && dcerpc.opnum == 3
```

```text
dcerpc.cn_bind_to_uuid == e3514235-4b06-11d1-ab04-00c04fc2dcd2
```

The operation filter also selects endpoint mapper requests. Follow the matching TCP stream and check its interface bind before interpreting an operation number.

TShark verified the packet counts and reported no malformed or truncated frames. Capture hashes are in [SHA256SUMS](../SHA256SUMS), and the exact rule replay results are in [validation.json](../Suricata/validation.json).
