# BPFDoor

This directory contains BPFDoor research artifacts collected for detection engineering and lab validation.

Contents may include:
- PCAPs built to model BPFDoor-related network behavior
- Suricata rules and testing notes
- a short description of the detection ideas being exercised
- reference material such as the Rapid7 whitepaper, Elastic research, or links to those sources

The current emphasis is on ICMP-related behavior, including Rapid7 `icmpShell`-inspired traits and classic BPFDoor ICMP magic-byte artifacts.

## Disabled-by-default local rule

SID `9955008`, `LOCAL BPFDoor ICMP 0x7255 magic-byte wake-up artifact`, is available in [bpfdoor-icmp-magic.rules](Suricata/bpfdoor-icmp-magic.rules). It replaces local SID `9002101` and is disabled by maintainer choice.

The actual rule line begins with `#`, so normal Suricata loading skips it. Pulling this repository does not enable it. Explicit local enablement or a rule-manager override can enable it. The example in `BPFDoor_Suricata_rules.md` is also commented out.

The active `feed/suricata/pb22.rules` is unchanged and does not include this SID. When this rule is incorporated into the feed, preserve its disabled-by-default state.
