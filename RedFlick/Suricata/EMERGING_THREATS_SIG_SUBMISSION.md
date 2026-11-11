# Emerging Threats SIG submission draft

## Forum fields

- **Topic title:** `SIG: ET MALWARE RedFlick DNSObserver HTTP C2 Check-in`
- **Category:** `Rule Signatures`
- **Tags:** `etopen`, `suricata`, `malware`, `pcaps`

The first three tags match the current pattern used by recent ET Open malware signature submissions; `pcaps` identifies that a review capture is included.[6]

## Post body

Hi all,

I put together a Suricata rule and a small synthetic PCAP for the DNSObserver HTTP registration behavior associated with the RedFlick activity described in public reporting.

Digital Security Lab Ukraine documented a scheduled task named `SecureDNSObserver` that periodically requests `/dns/request?ui=$encodedValue` with the exact User-Agent `DNSObserver`, then pipes the server response into `cmd.exe`. The encoded value represents a victim fingerprint built from domain, host, and user information.[1]

Microsoft later described RedFlick as a Star Blizzard malware delivery technique that uses scheduled tasks, noted overlap with the Digital Security Lab Ukraine reporting, and listed `secure-dns-hub[.]com` among RedFlick and CosmicPulse related infrastructure.[2]

The proposed rule is host independent so that it detects the documented HTTP request shape rather than one short lived domain or IP.

## Proposed rule

The SID is a temporary local submission identifier and can be replaced during ET review.

```suricata
alert http any any -> any any (msg:"LOCAL MALWARE RedFlick DNSObserver HTTP C2 Check-in"; flow:established,to_server; http.method; content:"GET"; startswith; endswith; http.uri; content:"/dns/request?ui="; startswith; pcre:"/^\/dns\/request\?ui=[A-Za-z0-9+\x2f=]{24,256}(?:&|$)/"; http.user_agent; content:"DNSObserver"; startswith; endswith; fast_pattern; reference:url,dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos/; classtype:trojan-activity; sid:9901201; rev:1;)
```

## Detection logic

The rule requires all of the following in one established client to server HTTP request:

- method exactly `GET`
- normalized URI beginning with `/dns/request?ui=`
- a `ui` value beginning with 24 to 256 Base64 compatible characters
- exact User-Agent `DNSObserver`

The source reporting establishes that the victim fingerprint is Base64 encoded. The 24 to 256 character bound is a detection design constraint used to reject obviously short values; it should not be treated as a universal protocol limit.[1]

`DNSObserver` is the explicit fast pattern. The rule does not match the reported domain or IP, which preserves coverage when infrastructure changes.

## PCAP and expected results

The test capture contains 40 packets and four separate HTTP exchanges:

| Packet span | HTTP request frame | Test role | Changed condition | Expected result |
| ---: | ---: | --- | --- | --- |
| 1 to 10 | 4 | Intended positive | None; complete conjunction | Alert |
| 11 to 20 | 14 | Negative control | User-Agent changed to `WindowsUpdateClient/10.0` | No alert |
| 21 to 30 | 24 | Negative control | URI changed to `/dns/status?ui=...` | No alert |
| 31 to 40 | 34 | Negative control | `ui` value changed to `short` | No alert |

The capture uses synthetic documentation addresses and cleartext HTTP. TShark decoded the four intended requests, the capture is in strict timestamp order, and the expert report contained no warnings or errors. These are packet and fixture checks, not a substitute for Suricata engine replay.

- **PCAP:** [redflick-dnsobserver-http.pcap](https://github.com/Pb-22/Network_Detections/raw/refs/heads/main/RedFlick/pcap/redflick-dnsobserver-http.pcap)
- **PCAP SHA-256:** `b997871a4151cea1a0e8649955f94f1f36f63b3eb6c6e534db02c913f6a6bdc7`
- **Visual explainer:** [redflick-explainer.png](https://github.com/Pb-22/Network_Detections/blob/main/RedFlick/pcap/redflick-explainer.png)
- **Browser explainer:** [redflick-explainer.xml](https://github.com/Pb-22/Network_Detections/blob/main/RedFlick/pcap/redflick-explainer.xml)
- **Rule and supporting files:** [RedFlick package](https://github.com/Pb-22/Network_Detections/tree/main/RedFlick)[4]

## ET Open coverage check

I downloaded the current ET Open Suricata 7.0.3 bundle on 2026-11-11. The server reported a last modified time of 2026-11-10 20:23:04 UTC. I searched all 54 `.rules` files for the exact literals `DNSObserver`, `/dns/request?ui=`, `secure-dns-hub`, and `RedFlick`; none were present. The downloaded archive SHA-256 was `fafbc7f016f407f41e1cb38348ecb9a5f7810e280484416b18f763a339068aa0`.[3]

This was an exact literal coverage check, not a claim that no broader or behaviorally overlapping ET rule exists.

## Validation status

- PCAP structure and HTTP fields: checked
- Positive and negative packet predicates: checked
- Suricata syntax test: not run on the publication host
- Suricata replay and observed SID counts: not run
- Expected result matrix: included above for review and replay

I am labeling the replay status explicitly so expected outcomes are not mistaken for observed engine results. I can provide revised captures or follow up with engine results if useful.

## Visibility and false negative boundaries

- The rule requires visibility into cleartext HTTP. It will not inspect ordinary encrypted HTTPS without a decrypted or post termination inspection point.
- It will miss variants that change the exact User-Agent, path, HTTP method, encoding alphabet, or value length.
- The rule detects the outbound registration or check-in request. It does not prove that the server returned a command, that `cmd.exe` executed it, or that CosmicPulse was installed.
- The PCAP is deterministic synthetic traffic derived from the reported request shape, not a wild victim capture.

## False positive considerations

The exact combination of method, path, encoded value shape, and User-Agent should be more selective than any one field alone. A benign or test application could still reproduce the same combination, so alerts should be correlated with the source endpoint, scheduled task evidence, command execution, WebDAV activity, or other RedFlick and CosmicPulse indicators.

## Suggested ET classification and metadata

Suggested starting values for ET review:

- **Ruleset:** ET Open
- **Category:** Malware
- **Classtype:** `trojan-activity`
- **Attack target:** `Client_Endpoint`
- **Deployment:** `Perimeter`
- **Affected product:** Windows client and server endpoints
- **Performance impact:** `Moderate` because the rule includes a bounded PCRE, with a selective exact User-Agent fast pattern
- **Confidence:** `Medium` pending wild capture or exact sample replay
- **Signature severity:** `Major`
- **Tags:** `RedFlick`, `Star_Blizzard`
- **TLS state:** `plaintext`
- **Target:** `src_ip`

These fields follow the current ET metadata vocabulary and are offered as review suggestions rather than claims that ET has approved the classification.[5]

Would this be a reasonable ET Open candidate? I am happy to adjust the direction, message, metadata, URI bound, or rule structure based on review.

Thanks!

## Sources

[1] https://dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos — Spearphishing via Fake URC 2026 Invitations Targets Ukrainian CSOs
[2] https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique — Star Blizzard refines phishing and malware delivery with the RedFlick technique
[3] https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz — ET Open rules for Suricata 7.0.3
[4] https://github.com/Pb-22/Network_Detections/tree/main/RedFlick — RedFlick Suricata rule and PCAP package
[5] https://community.emergingthreats.net/t/signature-metadata/96 — Emerging Threats signature metadata
[6] https://community.emergingthreats.net/t/sigs-packclient-stream-aware-signatures-and-core-startup-correlation/3461 — Recent ET Open malware signature submission example
