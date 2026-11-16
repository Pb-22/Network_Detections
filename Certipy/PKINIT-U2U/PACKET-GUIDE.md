# Packet guide

Frame numbers are **one-based in each distributed PCAP**. The captures preserve timestamps and packet-record bytes. Successful issuance refers to a KDC response, not client-side extraction or application authorization.

## Case map

| PCAP stem | Packets | Key frames | Packet interpretation |
|---|---:|---|---|
| `positive-pkinit-u2u` | 28 | 6 AS-REQ; 11 AS-REP; 21 TGS-REQ; 24 TGS-REP | PA-PK-AS-REQ 16 and PA-PK-AS-REP 17; U2U options `0x40810018`, one additional ticket; target and reply client `pku-alice` |
| `negative-pkinit-no-hash` | 15 | 6 / 11 | PKINIT succeeds; no follow-on TGS exchange |
| `negative-password-service` | 31 | 4 / 5 initial AS-REQ / preauth-required error; 13 / 15 password AS exchange; 24 / 27 TGS exchange | PA-ENC-TIMESTAMP 2, ordinary CIFS service; TGS options `0x40810010`, no additional ticket |
| `negative-pkinit-service` | 27 | 6 / 11 PKINIT; 20 / 23 TGS exchange | CIFS service; TGS options `0x40810010`, no additional ticket |
| `negative-password-self-u2u` | 32 | 13 / 15 password AS; 25 / 28 TGS exchange | Same-account U2U, options `0x40810018` and one additional ticket, but no PKINIT |
| `negative-cross-principal` | 43 | 6 / 11 Alice PKINIT; 21 / 26 Bob PKINIT; 36 / 39 TGS exchange | Request authenticating TGT belongs to Bob; requested service/additional ticket belongs to Alice; response client is Bob |
| `benign-rdp-nla-u2u` | 134 | 47 / 49 password AS; 58 / 61 ordinary TERMSRV; 91 / 94 U2U | Native Windows RDP/NLA request at 91 has options `0x40810008`, one additional ticket and a successful TGS-REP at 94 |
| `partial-view-positive` | 13 | 6 / 9 TGS exchange | Original positive frames 21 / 24, renumbered after omitting original frames 1–15; no AS exchange remains |

The RDP control was captured with zero reported capture drops. The interactive desktop was denied; do **not** describe it as a successful interactive RDP login. It nevertheless contains the legitimate U2U request/reply behavior needed for this negative control. Its service is `TERMSRV/idnet-dc1.idnet.superimportantbusiness.com`, not a self-targeted account service.

In Wireshark, expand the **outer** TGS-REQ `req-body` when reading `sname`. A decoded packet can show several service names: the PA-TGS-REQ AP-REQ's authenticating ticket, the requested target, and an additional ticket. A flat TShark `kerberos.SNameString` column concatenates these; it does not imply that every name is the requested service. Similarly, a TGS-REQ can display message types `12,14` because it contains an AP-REQ.

The clear request body may omit `cname`. Do not substitute the source IP as the principal: identify the previously issued AS TGT, compare its ticket content with the AP-REQ TGT and the additional ticket, then check the TGS response client and ticket service.

## Inspect locally

Examples, from the package directory:

```sh
tshark -n -r pcap/positive-pkinit-u2u.pcap -Y kerberos -T fields \
  -e frame.number -e kerberos.msg_type -e kerberos.padata_type \
  -e kerberos.CNameString -e kerberos.SNameString \
  -e kerberos.kdc_options -e kerberos.additional_tickets

tshark -n -r pcap/benign-rdp-nla-u2u.pcap \
  -Y 'frame.number == 91 || frame.number == 94' -V
```

No decryption keys are required for these wire observations. Wireshark decodes wire `0x8` as ENC-TKT-IN-SKEY; Zeek 9.0.0's event-field naming differs. See the [parser notes](DETECTOR-GUIDE.md#zeek-900-parser-compatibility).

## Explicit partial-view derivation

`partial-view-positive.pcap` is the original positive's **24-byte classic-PCAP global header plus its original packet records 16 onward** (one-based). This preserves packet headers, timestamps, captured lengths, payloads and ordering. It does not synthesize a request, change account names, or rewrite any packet. Global frame numbering necessarily restarts at 1 when opened as the derived file. Its expected zero detection demonstrates missing prerequisite visibility, not a true negative.

To reproduce this derivation using only Python's standard library:

```python
from pathlib import Path
import struct
raw = Path('pcap/positive-pkinit-u2u.pcap').read_bytes()
assert raw[:4] == b'\xd4\xc3\xb2\xa1'  # This exact fixture: little-endian classic PCAP
records = []
pos = 24
while pos < len(raw):
    captured = struct.unpack_from('<IIII', raw, pos)[2]
    end = pos + 16 + captured
    assert end <= len(raw)
    records.append(raw[pos:end])
    pos = end
assert pos == len(raw)
derived = raw[:24] + b''.join(records[15:])
assert derived == Path('pcap/partial-view-positive.pcap').read_bytes()
```

## Dissector caveats are not capture truncation

TShark 4.2.2 flags BER/ASN.1 fields in PKINIT AS-REP frame 11 in the positive, PKINIT-only and PKINIT/service files, and frames 11 and 26 in the cross-principal file. It reports an expected-tag mismatch inside the decoded PKINIT reply. The same TShark version marks RDP-control frame 34 with a **CLDAP dissector recursion assertion**. These are recorded parser anomalies, not silently removed frames. Their captured lengths equal their wire lengths; no distributed capture has a `frame.cap_len < frame.len` frame. The authentic original PCAPs remain unchanged.

Use both conditions when checking captures:

```sh
tshark -n -r pcap/positive-pkinit-u2u.pcap \
  -Y '_ws.malformed || frame.cap_len < frame.len' -T fields \
  -e frame.number -e frame.cap_len -e frame.len -e _ws.expert.message
```

A zero TShark exit status does not mean no `_ws.malformed` nodes. Conversely, a TShark anomaly does not establish that Zeek failed: `validation.json` records the exact Zeek replay counts and reporter-error gate separately.
