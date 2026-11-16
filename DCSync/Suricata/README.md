# Detecting DRSUAPI DsGetNCChanges

This rule identifies an established client request for operation 3 on the DRSUAPI interface. Microsoft names this operation `IDL_DRSGetNCChanges`; tools and investigation notes also commonly call it `DsGetNCChanges`.

## Rule

Download [dcsync-dsgetncchanges.rules](dcsync-dsgetncchanges.rules) as the directly loadable copy.

```suricata
alert dcerpc any any -> $HOME_NET any (msg:"LOCAL POLICY DRSUAPI DsGetNCChanges Observed - Validate Source Replication Role"; flow:established,to_server; dcerpc.iface:e3514235-4b06-11d1-ab04-00c04fc2dcd2; dcerpc.opnum:3; reference:url,learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410; reference:url,attack.mitre.org/techniques/T1003/006/; classtype:policy-violation; sid:1000206; rev:1; metadata:attack_target Server_Endpoint, created_at 2026_11_15, deployment Internal, performance_impact Low, confidence High, signature_severity Major, tag directory_replication, updated_at 2026_11_15, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1003, mitre_technique_name OS_Credential_Dumping; target:dest_ip;)
```

## How it works

| Condition | Purpose |
| --- | --- |
| `alert dcerpc` | Uses the DCE/RPC application parser |
| `any any -> $HOME_NET any` | Includes internal sources and dynamic destination ports while keeping the destination inside the configured network scope |
| `flow:established,to_server` | Inspects established client requests |
| `dcerpc.iface:e3514235-4b06-11d1-ab04-00c04fc2dcd2` | Requires the Active Directory replication interface |
| `dcerpc.opnum:3` | Selects the replication operation within that interface |
| `target:dest_ip` | Identifies the directory server as the protocol target |

An RPC operation number has meaning within its interface. Endpoint mapper also uses operation 3, so an operation only rule would alert on unrelated requests. The supplied negative control contains that exact case and remains silent.

The parser maintains the interface context for the request. The rule therefore needs no raw UUID byte patterns, PCRE, flowbits, or xbits. Suricata 8.0.8 engine analysis creates both direct DCE/RPC and SMB DCE/RPC inspection paths from this single signature. The supplied capture results exercise direct DCE/RPC over TCP.

## Replay results

The exact rule passed syntax validation and engine analysis on Suricata 8.0.8. Replay returned:

| Capture | SID 1000206 alerts |
| --- | ---: |
| `negative-drsuapi-cracknames.pcap` | 0 |
| `positive-drsuapi-dsgetncchanges.pcap` | 1 |
| `dcsync-positive-negative-combined.pcap` | 1 |

[validation.json](validation.json) records these results and the rule checksum. The [capture guide](../pcap/README.md) identifies the relevant frames.

## Reproduce the combined replay

Run from the repository root with Suricata 8.0.8 and its standard configuration:

```sh
mkdir -p dcsync-output
suricata -T -c /etc/suricata/suricata.yaml -S DCSync/Suricata/dcsync-dsgetncchanges.rules --set 'vars.address-groups.HOME_NET=[10.77.10.10]' -l dcsync-output
suricata -c /etc/suricata/suricata.yaml -S DCSync/Suricata/dcsync-dsgetncchanges.rules --set 'vars.address-groups.HOME_NET=[10.77.10.10]' --runmode single -r DCSync/pcap/dcsync-positive-negative-combined.pcap -l dcsync-output
```

The combined replay produces one alert. The address override includes the supplied capture destination; use the appropriate `$HOME_NET` for the monitored environment during deployment. The rule uses local SID `1000206`, so check for a collision with existing local rules before loading it.

## Triage and visibility

1. Confirm the destination is a domain controller.
2. Identify the source host and authenticated principal.
3. Check whether the source is an expected replication partner or an approved synchronization, backup, recovery, or identity service.
4. Review recent account privilege changes and related authentication activity.
5. Investigate unexpected sources for replication abuse and credential access.

The detector reports the requested operation and leaves authorization to the analyst. A successful response and the data returned require separate inspection. The supplied positive contains a successful response; that response is not a condition in the signature.

Capture the interface negotiation and request so the parser can associate the operation with DRSUAPI. Encryption that conceals the RPC exchange, including SMB encryption or an outer encrypted tunnel, limits this visibility. The rule has no built in threshold, leaving repeated transactions available for review and local tuning.

## References

- [Microsoft DRSUAPI interface](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410)
- [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [Suricata DCE/RPC keywords](https://docs.suricata.io/en/suricata-8.0.8/rules/dcerpc-keywords.html)
