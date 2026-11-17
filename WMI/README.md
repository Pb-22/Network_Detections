# WMI Command-Output Encoding Detection

This package detects a WMI-style process-creation request that invokes `certutil -encodehex` to encode command output. The pattern follows output handling observed in NetExec and the wmiexec-RegOut implementation. The rule selects the encoding request rather than every process creation in the surrounding exchange.

The request combines `Win32_Process`, `Create`, the serialized command parameters, and the observed encoder mode. The Suricata signature inspects the reassembled TCP stream, so the command can span several TCP packets.

## Contents

| Directory | Contents |
| --- | --- |
| [Suricata](Suricata/) | Loadable rule, matching conditions, replay results, and triage guidance |
| [pcap](pcap/) | One combined capture, sixteen separate cases, and a packet-by-packet case map |

The rule is included in the [subscription feed](../feed/). Load either the aggregate feed or the standalone rule file, not both copies.

## Replay results

Suricata 8.0.8 loaded SID 9955009 revision 12 successfully. The authentic execution produced one alert. The combined capture produced seven alerts in both `single` and `autofp` replay modes.

The matrix contains six intended positives and ten intended negatives. All six positives alert. Nine negatives remain quiet; the wrong-interface control also produces one alert. The rule recognizes the request pattern without binding it to the negotiated RPC interface.

| Replay | SID 9955009 alerts |
| --- | ---: |
| Authentic execution | 1 |
| Combined capture, single | 7 |
| Combined capture, autofp | 7 |

The [detection guide](Suricata/README.md) contains the full comparison table. The [capture guide](pcap/README.md) maps each case to its separate file and combined packet range.

## Investigating an alert

Identify the source system and account, examine the remote command, and establish whether the output-handling workflow is authorized. Administrative automation and security testing provide competing explanations for the same operation. Review related process, file, registry, and authentication records to establish what the remote execution accomplished.

The alert identifies an encoding request. It does not establish malicious intent or completion of the surrounding output-retrieval workflow.

## Integrity

[SHA256SUMS](SHA256SUMS) records the package file hashes. Run `sha256sum --check SHA256SUMS` from this directory.

## References

- [Microsoft WMI protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cbce28cd-fd45-4df1-9ec8-416e6bb33691)
- [wmiexec-RegOut implementation](https://github.com/XiaoliChan/wmiexec-RegOut)
- [Suricata payload matching](https://docs.suricata.io/en/suricata-8.0.8/rules/payload-keywords.html)
