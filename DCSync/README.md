# DCSync Directory Replication Detection

This package detects `DsGetNCChanges` requests on the Active Directory replication interface. DCSync uses this operation to request directory data through the same protocol used for legitimate replication. The useful investigation question is whether the source is expected to perform that work.

The Suricata rule matches the DRSUAPI interface UUID and operation number together. The captures include a successful replication request, a control that uses other operations on the same interface, and a combined capture for reviewing both cases.

## Contents

| Directory | Contents |
| --- | --- |
| [Suricata](Suricata/) | Loadable rule, detection logic, replay instructions, and triage guidance |
| [pcap](pcap/) | Positive, negative, and combined captures with packet references |

## Replay results

Suricata 8.0.8 loaded the rule successfully and produced these results:

| Capture | Packets | Alerts from SID 1000206 |
| --- | ---: | ---: |
| [Negative control](pcap/negative-drsuapi-cracknames.pcap) | 48 | 0 |
| [Positive replication request](pcap/positive-drsuapi-dsgetncchanges.pcap) | 52 | 1 |
| [Combined capture](pcap/dcsync-positive-negative-combined.pcap) | 100 | 1 |

The replay used the exact supplied rule and included the capture destination, `10.77.10.10`, in `$HOME_NET`. The captures contain authentic traffic from a controlled lab exercise using lab identities. The replication exchange runs over a dynamic TCP RPC endpoint.

## Investigating an alert

Confirm that the destination is a domain controller, identify the source system and authenticated principal, and establish whether they are authorized to replicate directory data. Domain controllers and approved directory services provide important competing explanations. Replication from an unexpected workstation or unfamiliar service account deserves closer investigation.

The alert identifies the replication operation. Source role, account privileges, and surrounding activity determine whether it represents DCSync abuse.

## Integrity

[SHA256SUMS](SHA256SUMS) records the rule, capture, documentation, and replay result hashes. Run `sha256sum --check SHA256SUMS` from this directory.

## References

- [Microsoft DRSUAPI interface and operation numbers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410)
- [MITRE ATT&CK: DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [Suricata 8.0.8 DCE/RPC keywords](https://docs.suricata.io/en/suricata-8.0.8/rules/dcerpc-keywords.html)
