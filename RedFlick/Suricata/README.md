# RedFlick DNSObserver Suricata Rules

ET Open publishes two complementary detections for the DNSObserver HTTP activity described by Digital Security Lab Ukraine. The first checks the complete request pattern. The second checks the exact User-Agent independently.

Download [redflick-dnsobserver.rules](redflick-dnsobserver.rules) for both loadable signatures. The file preserves the published ET rule bytes, SIDs, and revisions.

## SID 2072753: CnC Check-In

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE RedFlick DNSObserver CnC Check-In"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/dns/request?ui="; startswith; pcre:"/^(?:[a-zA-Z0-9\x2b\x2f\x3d]{24,256}(?:&|$))/R"; http.user_agent; bsize:11; content:"DNSObserver"; fast_pattern; reference:url,dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos/; reference:url,community.emergingthreats.net/t/sig-malware-redflick-dnsobserver-http-c2-check-in/3527; classtype:trojan-activity; sid:2072753; rev:1; metadata:affected_product Windows_Client, attack_target Client_Endpoint, tls_state TLSDecrypt, created_at 2026_11_13, deployment Perimeter, deployment SSLDecrypt, malware_family RedFlick, confidence High, signature_severity Critical, tag c2, updated_at 2026_11_13, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol; target:src_ip;)
```

This rule requires an established client request from `$HOME_NET` to `$EXTERNAL_NET`, with all of these conditions:

- HTTP method contains `GET`.
- Normalized URI starts with `/dns/request?ui=`.
- The following value contains 24 to 256 characters from the Base64 alphabet, followed by `&` or the end of the URI.
- User-Agent is exactly `DNSObserver`.

The URI prefix anchors a relative PCRE using `/R`. The expression validates the value immediately after the prefix. It checks an alphabet and length constraint, rather than decoding the value or validating Base64 padding.

The User-Agent uses `bsize:11` and an 11 byte case sensitive content match. Together they enforce exact equality. `DNSObserver` is the fast pattern, allowing the engine to prefilter requests using that marker.

## SID 2072754: User-Agent Observed

```suricata
alert http any any -> $EXTERNAL_NET any (msg:"ET MALWARE RedFlick DNSObserver User-Agent Observed"; flow:established,to_server; http.user_agent; bsize:11; content:"DNSObserver"; fast_pattern; reference:url,dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos/; reference:url,community.emergingthreats.net/t/sig-malware-redflick-dnsobserver-http-c2-check-in/3527; classtype:trojan-activity; sid:2072754; rev:1; metadata:affected_product Windows_Client, attack_target Client_Endpoint, tls_state TLSDecrypt, created_at 2026_11_13, deployment Perimeter, deployment SSLDecrypt, malware_family RedFlick, confidence High, signature_severity Major, updated_at 2026_11_13; target:src_ip;)
```

This rule requires an established client request to `$EXTERNAL_NET` with the exact User-Agent `DNSObserver`. Its source is `any`, and it places no restrictions on method, URI, or query value.

The broader rule preserves coverage when those other request fields change. Treat it as an observed campaign marker and investigate the source. Public reporting documents this exact value in the malicious command, while benign prevalence still depends on the monitored environment.

## Relationship between the rules

Each signature works independently. Loading both can produce two alerts for one complete check in request. Compare flow and HTTP transaction details before counting those alerts as separate events.

If ET Open is already enabled, use the rules it supplies rather than loading an additional copy of the same SIDs.

## Validation and replay

Suricata 8.0.8 syntax validation and engine analysis passed. The [40 packet capture](../pcap/redflick-dnsobserver-http.pcap) produced:

| Test case | SID 2072753 | SID 2072754 |
| --- | ---: | ---: |
| Complete check in pattern | 1 | 1 |
| Different User-Agent | 0 | 0 |
| Different path | 0 | 1 |
| Short `ui` value | 0 | 1 |
| Total | 1 | 3 |

Run from the repository root with Suricata 8.0.8 and its standard configuration:

```sh
mkdir -p redflick-output
suricata -c /etc/suricata/suricata.yaml -S RedFlick/Suricata/redflick-dnsobserver.rules --set 'vars.address-groups.HOME_NET=[192.0.2.10]' --set 'vars.address-groups.EXTERNAL_NET=[198.51.100.20]' --runmode single -r RedFlick/pcap/redflick-dnsobserver-http.pcap -l redflick-output
```

The variable overrides map the fixture addresses without changing the published signatures. Use the monitored network's own variables during deployment.

[validation.json](validation.json) records the exact file checksum and observed counts. The [capture guide](../pcap/README.md) explains each request.

## Visibility

The rules inspect HTTP fields and require cleartext or decrypted HTTP visibility. Their address scopes also matter: the full rule covers `$HOME_NET` to `$EXTERNAL_NET`, while the broader rule accepts any source to `$EXTERNAL_NET`. Changes to the exact User-Agent evade both signatures; changes to the other request fields can affect the full signature while leaving the broader marker visible.

## References

- [Digital Security Lab Ukraine analysis](https://dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos/)
- [ET reviewer announcement](https://community.emergingthreats.net/t/sig-malware-redflick-dnsobserver-http-c2-check-in/3527/4)
- [Published ET Open rules](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-malware.rules)
