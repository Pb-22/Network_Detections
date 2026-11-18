# WMI Combined Recovery-Inhibition Command

This signature identifies a WMI-style process-creation request that combines deletion of recovery data with explicit disabling of Windows recovery. The command includes both actions in the same serialized input value. MITRE ATT&CK describes these recovery-inhibition behaviors under **T1490: Inhibit System Recovery**.[^1]

| Field | Value |
| --- | --- |
| Message | HUNTING WMI-style combined recovery-inhibition command request |
| SID / revision | 9955010 / 7 |
| ATT&CK tactic | TA0040: Impact |
| ATT&CK technique | T1490: Inhibit System Recovery |
| Inspection | Reassembled client-to-server TCP stream |
| Destination scope | `$HOME_NET` |

## Rule

Use [wmi-recovery-inhibition.rules](wmi-recovery-inhibition.rules) as the directly loadable copy. The signature below is one physical line. The [wrapped reading view](wmi-recovery-inhibition.html) displays the same rule with visual line wrapping.

```suricata
alert tcp any any -> $HOME_NET any (msg:"HUNTING WMI-style combined recovery-inhibition command request"; flow:established,to_server,only_stream; content:"|05 00 00 83 10 00 00 00|"; content:"|18 00|"; distance:14; within:2; content:"|57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00|"; distance:0; within:256; nocase; content:"|43 00 72 00 65 00 61 00 74 00 65 00 00 00|"; distance:0; within:128; nocase; content:"__PARAMETERS|00 01|"; distance:0; within:2048; content:"|72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00|"; distance:0; within:1024; nocase; fast_pattern; content:"|64 00 65 00 6c 00 65 00 74 00 65 00|"; nocase; pcre:"/(?(DEFINE)(?<S>(?:[\x20\x09]\x00){1,8})(?<O>(?:[\x20\x09]\x00){0,8})(?<P>(?:[A-Za-z]\x00\x3a\x00\x5c\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x33\x00\x32\x00\x5c\x00|\x25\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x52\x00\x6f\x00\x6f\x00\x74\x00\x25\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x33\x00\x32\x00\x5c\x00)?)(?<D>(?:(?&P)\x76\x00\x73\x00\x73\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?&S)\x64\x00\x65\x00\x6c\x00\x65\x00\x74\x00\x65\x00(?&S)\x73\x00\x68\x00\x61\x00\x64\x00\x6f\x00\x77\x00\x73\x00(?&S)(?:\x2f\x00\x61\x00\x6c\x00\x6c\x00(?:(?&S)\x2f\x00\x71\x00\x75\x00\x69\x00\x65\x00\x74\x00)?|\x2f\x00\x71\x00\x75\x00\x69\x00\x65\x00\x74\x00(?&S)\x2f\x00\x61\x00\x6c\x00\x6c\x00)|(?&P)\x77\x00\x6d\x00\x69\x00\x63\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?&S)\x73\x00\x68\x00\x61\x00\x64\x00\x6f\x00\x77\x00\x63\x00\x6f\x00\x70\x00\x79\x00(?&S)\x64\x00\x65\x00\x6c\x00\x65\x00\x74\x00\x65\x00(?:(?&S)\x2f\x00\x6e\x00\x6f\x00\x69\x00\x6e\x00\x74\x00\x65\x00\x72\x00\x61\x00\x63\x00\x74\x00\x69\x00\x76\x00\x65\x00)?|(?&P)\x77\x00\x62\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?&S)\x64\x00\x65\x00\x6c\x00\x65\x00\x74\x00\x65\x00(?&S)\x63\x00\x61\x00\x74\x00\x61\x00\x6c\x00\x6f\x00\x67\x00(?:(?&S)\x2d\x00\x71\x00\x75\x00\x69\x00\x65\x00\x74\x00)?))(?<R>(?&P)\x62\x00\x63\x00\x64\x00\x65\x00\x64\x00\x69\x00\x74\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?&S)\x2f\x00\x73\x00\x65\x00\x74\x00(?&S)(?:\x7b\x00\x64\x00\x65\x00\x66\x00\x61\x00\x75\x00\x6c\x00\x74\x00\x7d\x00|\x7b\x00\x63\x00\x75\x00\x72\x00\x72\x00\x65\x00\x6e\x00\x74\x00\x7d\x00)(?&S)\x72\x00\x65\x00\x63\x00\x6f\x00\x76\x00\x65\x00\x72\x00\x79\x00\x65\x00\x6e\x00\x61\x00\x62\x00\x6c\x00\x65\x00\x64\x00(?&S)\x6e\x00\x6f\x00)(?<J>(?&O)\x26\x00(?:\x26\x00)?(?&O))(?<F>\x22\x00(?:[\x20-\x21\x23-\x7e]\x00){1,160}\x22\x00)(?<B>(?:(?&D)(?&J)(?&R)|(?&R)(?&J)(?&D))))\x05\x00\x00\x83\x10\x00\x00\x00.{14}\x18\x00(?>(?!.{0,256}\x05\x00[\x00-\x13][\x03\x83]\x10\x00\x00\x00).{0,256}\x57\x00\x69\x00\x6e\x00\x33\x00\x32\x00\x5f\x00\x50\x00\x72\x00\x6f\x00\x63\x00\x65\x00\x73\x00\x73\x00\x00\x00)(?>(?!.{0,128}\x05\x00[\x00-\x13][\x03\x83]\x10\x00\x00\x00).{0,128}\x43\x00\x72\x00\x65\x00\x61\x00\x74\x00\x65\x00\x00\x00)(?>(?!.{0,2048}\x05\x00[\x00-\x13][\x03\x83]\x10\x00\x00\x00).{0,2048}__PARAMETERS\x00\x01)\x63\x00\x6d\x00\x64\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?&S)(?:\x2f\x00\x51\x00(?&S))?\x2f\x00\x63\x00(?&S)(?:(?&B)|\x28\x00(?&O)(?&B)(?&O)\x29\x00)(?:(?&S)\x31\x00\x3e\x00(?&S)(?&F)(?&S)\x32\x00\x3e\x00\x26\x00\x31\x00)?(?:[\x20\x09]\x00){0,256}\x00\x00/si"; reference:url,attack.mitre.org/techniques/T1490/; classtype:policy-violation; sid:9955010; rev:7; metadata:deployment Internal, confidence Low, signature_severity Major, created_at 2026_11_18, updated_at 2026_11_18, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1490, mitre_technique_name Inhibit_System_Recovery; target:dest_ip;)
```

SID `9955010` is included in the [subscription feed](../../../feed/). Load either the aggregate feed or the standalone file, not both copies.

## Detection logic

`Win32_Process.Create` accepts the command line for a new process.[^2] In the WMI protocol, `IWbemServices::ExecMethod` carries a class/object path, method name, and input parameters; its operation number is 24.[^3]

The signature selects the observed request framing, the `Win32_Process` class, `Create`, and the serialized command parameter. Its command grammar combines one deletion action with one recovery-disabling action:

| Required part | Selected command forms |
| --- | --- |
| Recovery-data deletion | `vssadmin delete shadows /all`, `wmic shadowcopy delete`, or `wbadmin delete catalog` |
| Recovery disabling | `bcdedit /set {default} recoveryenabled no` or the corresponding `{current}` form |
| Association | Both parts in one command value, joined by `&` or `&&`, in either order |

The supplied variants cover executable names with and without `.exe`, the selected System32 paths, case and whitespace changes, and a parenthesized command with stdout/stderr capture. The parser requires complete executable and argument tokens and a terminated UTF-16LE value. Echoed and commented command text remain outside that grammar.

Seven content checks provide literal gates before one bounded PCRE. The 30-byte UTF-16LE `recoveryenabled` literal is the fast pattern. Atomic field-selection groups retain the selected class, method and parameter occurrence while the command grammar is evaluated.

The rule is standalone. It uses standard network scope and packet-visible request contents; it requires no account lists, management-host inventories, flowbits, xbits or Lua.

## Replay results

Suricata 8.0.8 loaded the exact rule successfully. All forty-one capture outcomes reproduce the recorded matrix with this message and the ATT&CK metadata.

| Case group | Type | Cases | Expected alerts per case | Observed alerts per case |
| --- | --- | ---: | ---: | ---: |
| Combined commands and supported variants | P | 16 | 1 | 1 |
| Quiet negative controls | N | 24 | 0 | 0 |
| Wrong RPC interface | N | 1 | 0 | 1 |

P means the combined-request rule should alert. N means it should remain quiet. Type describes the detection objective, independently of operator authorization.

The controls include each action alone, actions split between separate requests, quoted or commented text, recovery queries and re-enabling, fake executable/value suffixes, and changed class, method, operation or direction. The positive set includes 512-, 96- and 17-byte TCP segments and a valid combined request following two coalesced single-action requests. Four additional `autofp` replays each produced one alert.

The [capture guide](../pcaps/README.md) contains every case and its observed count. [validation.json](validation.json) binds the results to the exact rule and capture hashes.

When replayed with the subscription feed, `combined-vss-bcd.pcap` produces one alert from recovery SID `9955010` and one from encoding SID `9955009`. The source conversation retains a separate command-output encoding request. These are different behavior matches; the standalone counts above refer only to the recovery rule. The wrong-interface capture also produces one alert from each rule. The split-actions control remains quiet for both.

## Packet construction

The combined-command and boundary captures are offline derivatives of the controlled WMI execution capture. Command substitutions preserve serialized field lengths, and IPv4/TCP checksums are recomputed. The payload changes retain the original RPC/NTLM signature bytes; authentication signatures are not recomputed for the derivatives. Coalesced conversations use distinct modeled call IDs, and segmentation variants preserve their constructed TCP stream bytes.

The original authorized execution, read-only query and sealed native comparison retain their original capture bytes. The test command substitutions were performed offline; no destructive recovery operation was executed to produce them.

## Visibility and interpretation

Inspection requires readable request arguments. The sealed native control hides those arguments. The signature follows the supplied little-endian, `0x83` request framing and command serialization. Its conservative next-header windows select the tested request layout.

The wrong-interface control produces one alert. The rule recognizes the WMI-style request pattern without authoritative negotiated-interface/context binding. TCP segmentation results establish stream-reassembly coverage for the supplied cases; RPC fragmentation is a separate mechanism.

The command grammar selects the documented shell forms, recovery flags and boot-entry identifiers. Other command wrappers, encoded commands, additional shell operations, different quoted executable paths or serialization layouts require their own coverage evidence.

An alert identifies a request containing both recovery-inhibition actions. Process-creation success and the resulting system changes require response or endpoint evidence. Microsoft documents separate return values for successful creation and errors.[^2]

## Investigating an alert

Review the full command, initiating system and account, target, related process activity, and backup or change records. Backup applications legitimately manage and delete snapshots through VSS.[^4] A request that also disables recovery deserves review in that operational context.

A deletion-only maintenance request remains outside this combined-action predicate. An authorized request containing both actions remains a behavior match. Source identity and asset role provide triage context without changing the core matching conditions.

## Offline replay

From this directory, using Suricata 8.0.8 and its standard configuration:

```sh
mkdir -p replay-output
suricata -T -c /etc/suricata/suricata.yaml -S wmi-recovery-inhibition.rules -l replay-output
suricata -c /etc/suricata/suricata.yaml -S wmi-recovery-inhibition.rules -r ../pcaps/combined-vss-bcd.pcap --set 'vars.address-groups.HOME_NET=10.77.0.0/16' --runmode single -k none -l replay-output
```

The positive capture produces one SID 9955010 alert. Replay `../pcaps/split-actions-across-requests.pcap` into a separate empty output directory to observe zero. Use the monitored environment's normal `$HOME_NET` value when loading the rule on a sensor.

## Reading and copying

The `.rules` file and this fenced block contain the same one-line signature. The HTML view uses CSS soft wrapping: it changes the display width while retaining the original code text. Markdown viewers choose their own code-block layout; the HTML view provides a wrapped reading surface.

## References

[^1]: [MITRE ATT&CK: Inhibit System Recovery (T1490)](https://attack.mitre.org/techniques/T1490).
[^2]: [Microsoft: Create method of the Win32_Process class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process).
[^3]: [Microsoft MS-WMI: IWbemServices::ExecMethod (Opnum 24)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cbce28cd-fd45-4df1-9ec8-416e6bb33691).
[^4]: [Microsoft: Volume Shadow Copy Service (VSS)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service).
