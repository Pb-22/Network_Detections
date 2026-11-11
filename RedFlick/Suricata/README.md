# RedFlick DNSObserver Suricata Rule

This rule detects the modeled RedFlick DNSObserver HTTP registration request. It requires an established client to server HTTP GET request with the documented URI structure, encoded value length, and exact User-Agent.

## Detection conditions

The rule requires all of the following:

- the HTTP method is exactly `GET`
- the normalized URI starts with `/dns/request?ui=`
- the `ui` value begins with 24 to 256 Base64 compatible characters
- the User-Agent is exactly `DNSObserver`

## Rule

```suricata
alert http any any -> any any (msg:"LOCAL MALWARE RedFlick DNSObserver HTTP C2 Check-in"; flow:established,to_server; http.method; content:"GET"; startswith; endswith; http.uri; content:"/dns/request?ui="; startswith; pcre:"/^\/dns\/request\?ui=[A-Za-z0-9+\x2f=]{24,256}(?:&|$)/"; http.user_agent; content:"DNSObserver"; startswith; endswith; fast_pattern; reference:url,dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos/; classtype:trojan-activity; sid:9901201; rev:1;)
```

The directly loadable one line copy is [`redflick-dnsobserver.rules`](redflick-dnsobserver.rules).

A copy ready Emerging Threats forum draft, including category, tags, evidence, PCAP matrix, coverage review, and validation boundaries, is available in [`EMERGING_THREATS_SIG_SUBMISSION.md`](EMERGING_THREATS_SIG_SUBMISSION.md).

## Test capture

The paired 40 packet capture and its visual explainer are in the [`pcap` directory](../pcap/). It contains one intended positive and three single property negative controls. Suricata replay remains pending, so the documented outcomes are expected rather than observed.

## Visibility and interpretation

This rule requires cleartext HTTP visibility. Matching the request conditions supports detection of the modeled registration marker, but the network alert alone does not establish successful command and control or host compromise.

## Reference

- [Spearphishing via Fake URC 2026 Invitations Targets Ukrainian CSOs](https://dslua.org/publications/spearphishing-via-fake-urc-2026-invitations-targets-ukrainian-csos/)
