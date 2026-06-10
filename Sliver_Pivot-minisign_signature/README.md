# Sliver Pivot Minisign Signature Hunting Rule

This folder contains a Suricata hunting rule for visible age and minisign key authentication material that can appear in Sliver style implant or pivot communication.

The rule is built for internal network visibility. It is intended for cases where one internal host talks to another internal host and a compromised system may be acting as a pivot into a more restricted network.

## What this detects

Sliver transport documentation describes a self managed key trust model for implants and pivots. During implant to implant pivot key exchange, peers can exchange age public keys and minisign signatures before later traffic is encrypted with an established symmetric session key.

This rule looks for the close combination of three things:

1. age style public key material beginning with a newline followed by `>age1`
2. the minisign marker `untrusted comment:`
3. the minisign marker `trusted comment:`

The combination is more useful than any one string alone. It points to visible key authentication material that can appear before encrypted pivot or implant traffic begins.

## Why this is connected to Sliver

The important point is that this key material is not just a random lab string. Sliver documentation states that generated implants embed age keys and minisign material at compile time. In other words, this functionality can be added when the implant is built. That strengthens the connection between this age plus minisign pattern and Sliver style implant or pivot behavior.

This does not mean every match is Sliver. It means the pattern is a useful hunting lead when it appears in unexpected internal TCP streams.

## Why HOME_NET to HOME_NET

The rule uses HOME_NET to HOME_NET because the main hunt is internal pivoting, not generic internet traffic. In many intrusions, an operator first lands on a workstation or server that can reach a more restricted network, then uses that host as a relay or pivot.

This scope keeps the rule focused on internal trust boundaries, workstation to workstation traffic, IT to OT paths, engineering workstation activity, and other internal movement candidates.

## Important caveat

This is a hunting signature, not proof of Sliver by itself.

age and minisign are legitimate technologies. A match can occur during benign internal development, release, package validation, update, or key management work. Analysts should review the host role, port, session context, surrounding traffic, and whether the systems involved are expected to exchange age or minisign material in cleartext.

## Validation summary

The rule was validated with an anonymized contiguous proof PCAP. The PCAP was anonymized only for lab identifying network artifacts: IP addresses, unicast MAC addresses, and hostnames plus NetBIOS hostname encodings were deterministically rewritten. The detection relevant age and minisign content and surrounding traffic structure were preserved.

Validation results:

1. Proposed rule: 4 alerts
2. `SURICATA STREAM excessive retransmissions` test rule: 0 alerts
3. `SURICATA HTTP unable to match response to request` test rule: 0 alerts

The proof capture is a contiguous time window cut, not packet level pruning or alert only extraction.

## Rule

See `Suricata_SIGs.md` for the Suricata rule.

## References

1. Bishop Fox Sliver documentation, Pivots: <https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Pivots.md>
2. Bishop Fox Sliver documentation, Transport Encryption: <https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Transport%20Encryption.md>
3. Sliver CPPImplant2 README: <https://github.com/MrAle98/Sliver-CPPImplant2/blob/master/README.md>
