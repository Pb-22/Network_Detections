# Detecting WMI-Style Command-Output Encoding

SID `9955009` identifies an established client request containing the observed process-creation and output-encoding pattern. It is one standalone signature, with no companion rules, flowbit setters, or Lua scripts.

## Rule

Download [wmi-command-output-encoding.rules](wmi-command-output-encoding.rules) as the directly loadable copy. Use that file when importing the rule into a sensor or replay tool.

```suricata
alert tcp any any -> $HOME_NET any (msg:"LOCAL HUNTING WMI-style certutil command-output encoding request"; flow:established,to_server,only_stream; content:"|05 00 00 83 10 00 00 00|"; content:"|18 00|"; distance:14; within:2; content:"|57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00|"; distance:0; within:256; nocase; content:"|43 00 72 00 65 00 61 00 74 00 65 00 00 00|"; distance:0; within:128; nocase; content:"|5f 5f 50 41 52 41 4d 45 54 45 52 53 00 01 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 51 00 20 00 2f 00 63 00 20 00 20 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 65 00 6e 00 63 00 6f 00 64 00 65 00 68 00 65 00 78 00 20 00 2d 00 66 00|"; distance:0; within:2048; nocase; fast_pattern; content:"|30 00 78 00 34 00 30 00 30 00 30 00 30 00 30 00 30 00 31 00 00 00|"; distance:0; within:1024; nocase; pcre:"/\x05\x00\x00\x83\x10\x00\x00\x00.{14}\x18\x00(?!.{0,256}\x05\x00[\x00-\x13][\x03\x83]\x10\x00\x00\x00).{0,256}W\x00i\x00n\x003\x002\x00_\x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00\x00\x00(?!.{0,128}\x05\x00[\x00-\x13][\x03\x83]\x10\x00\x00\x00).{0,128}C\x00r\x00e\x00a\x00t\x00e\x00\x00\x00(?!.{0,2048}\x05\x00[\x00-\x13][\x03\x83]\x10\x00\x00\x00).{0,2048}__PARAMETERS\x00\x01c\x00m\x00d\x00\x2e\x00e\x00x\x00e\x00\x20\x00\x2f\x00Q\x00\x20\x00\x2f\x00c\x00\x20\x00\x20\x00c\x00e\x00r\x00t\x00u\x00t\x00i\x00l\x00\x20\x00\x2d\x00e\x00n\x00c\x00o\x00d\x00e\x00h\x00e\x00x\x00\x20\x00\x2d\x00f\x00/si"; pcre:"/\G(?:[^\x00]\x00){0,512}0\x00x\x004\x000\x000\x000\x000\x000\x000\x001\x00\x00\x00/Rsi"; reference:url,learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cbce28cd-fd45-4df1-9ec8-416e6bb33691; reference:url,github.com/XiaoliChan/wmiexec-RegOut; classtype:misc-activity; sid:9955009; rev:12; metadata:affected_product Windows, attack_target Client_Endpoint, deployment Internal, confidence Low, signature_severity Informational, created_at 2026_11_17, updated_at 2026_11_17; target:dest_ip;)
```

SID `9955009` is also included in the [subscription feed](../../feed/). Load either that aggregate or the standalone file, not both copies.

## How it works

| Condition | Purpose |
| --- | --- |
| `any any -> $HOME_NET any` | Includes internal lateral traffic and dynamic destination ports |
| `flow:established,to_server,only_stream` | Inspects reassembled client-to-server TCP data |
| Observed RPC request header and operation 24 | Selects the request framing used in the captured execution |
| UTF-16LE `Win32_Process` and `Create` | Requires the process class and method |
| Serialized `__PARAMETERS` and the command prefix | Requires direct invocation of the observed encoder command |
| UTF-16LE `0x40000001` and the command terminator | Requires the observed encoding mode and string ending |
| Bounded request checks | Rejects the supplied cross-request splice and commented-command controls |
| `target:dest_ip` | Identifies the remote execution destination as the target |

The command prefix is `cmd.exe /Q /c  certutil -encodehex -f`; there are two spaces between `/c` and `certutil` in the observed serialization. File names are variable within the bounded command tail. Case-insensitive matches cover the supplied case-variation control.

Six content checks provide literal gates before two bounded PCREs. The 88-byte fast pattern combines the serialized parameter marker and encoder prefix. The request validator owns the encoding-prefix endpoint; the relative command-tail validator continues from that point.

## Comparison results

The table records exact alert counts on Suricata 8.0.8. Type P means the encoding rule should alert; N means it should remain quiet. These labels describe the narrow encoding objective, not malicious versus authorized activity.

| Test | Type | PT 10001999 | PAW 3300308 | SID 9955009 |
| --- | --- | ---: | ---: | ---: |
| Authentic execution | P | 1 | 4 | 1 |
| Native encrypted control | N | 0 | 0 | 0 |
| Visible read-only WMI query | N | 0 | 0 | 0 |
| Prefix before encoding is visible | N | 1 | 2 | 0 |
| 512-byte TCP segments | P | 1 | 4 | 1 |
| 96-byte TCP segments | P | 1 | 0 | 1 |
| 17-byte TCP segments | P | 1 | 0 | 1 |
| Wrong RPC interface | N | 1 | 4 | 1 |
| Wrong operation number | N | 1 | 4 | 0 |
| Wrong class | N | 0 | 0 | 0 |
| Wrong method | N | 0 | 0 | 0 |
| Wrong encoding mode | N | 1 | 4 | 0 |
| Case variation | P | 0 | 0 | 1 |
| Coalesced matching requests | P | 1 | 1 | 1 |
| Evidence split across requests | N | 1 | 1 | 0 |
| Commented-out encoder command | N | 1 | 1 | 0 |

PT and PAW cover broader process-creation behavior. Their alerts on some encoding-negative cases can therefore be consistent with their own objectives. PT's source-based ten-second suppression accounts for its single alert on the authentic exchange; the encoding rule selects one stage of that exchange.

The wrong-interface row demonstrates the interface boundary directly: the serialized process and encoding pattern matches even when the RPC interface is changed. The signature does not maintain a negotiated interface/context association.

## Replay

From the repository root, using Suricata 8.0.8 and its standard configuration:

```sh
mkdir -p wmi-output
suricata -T -c /etc/suricata/suricata.yaml -S WMI/Suricata/wmi-command-output-encoding.rules --set 'vars.address-groups.HOME_NET=10.77.0.0/16' -l wmi-output
suricata -c /etc/suricata/suricata.yaml -S WMI/Suricata/wmi-command-output-encoding.rules -r WMI/pcap/wmi-command-output-encoding-combined.pcap --set 'vars.address-groups.HOME_NET=10.77.0.0/16' --runmode single -k none -l wmi-output
```

The combined replay produces seven alerts. Set `$HOME_NET` for the monitored environment when deploying the rule. Replace the PCAP path with a file from `pcap/separate/` to examine one case. [validation.json](validation.json) records the exact rule and capture hashes with observed counts.

## Visibility and interpretation

Inspection requires readable request arguments. The supplied native encrypted control produces zero alerts because those arguments are sealed. TCP reassembly covers the tested 512-, 96-, and 17-byte segment variants; TCP segmentation and RPC fragmentation are different mechanisms.

Coverage follows the observed little-endian request framing, command wrapper, argument order, UTF-16LE representation, and bounded field spacing. The pattern can occur in authorized remote administration as well as offensive tooling. Investigate the initiating host, account, command, destination role, and surrounding endpoint activity.

## References

- [Microsoft WMI protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cbce28cd-fd45-4df1-9ec8-416e6bb33691)
- [wmiexec-RegOut implementation](https://github.com/XiaoliChan/wmiexec-RegOut)
- [Suricata payload matching](https://docs.suricata.io/en/suricata-8.0.8/rules/payload-keywords.html)
- [PT rule](https://rules.evebox.org/app/search?q=10001999)
- [PAW rule](https://rules.evebox.org/pub/pawpatrules/3300308)
