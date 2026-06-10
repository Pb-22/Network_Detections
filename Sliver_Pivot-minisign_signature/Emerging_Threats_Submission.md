# SIG: Possible Sliver Pivot or Implant Peer Key Material in Internal TCP Stream

Hi all,

I wanted to share a Suricata hunting rule and an anonymized proof PCAP for review. The rule looks for age style public key material followed by minisign signature comment markers in an internal TCP stream. The intended use is internal hunting for Sliver family, Sliver derived, or similar implant key exchange material, especially where an operator may be pivoting through one internal host toward a more restricted network.

## Primary sources

1. Bishop Fox Sliver documentation on pivots and transport encryption.[^1][^2]
2. A public Sliver compatible C++ implant project that shows Sliver derived key and minisign material embedded in generated implant code.[^3]

## Background

Sliver pivots are meant to route C2 traffic through implants. The Sliver documentation describes using one existing session to create a pivot listener, then generating another implant that connects to that listener. The same documentation notes that pivots are useful when a restricted subnet cannot route directly to the internet and must egress through another implant in a less restricted subnet.[^1]

The transport encryption documentation is the direct basis for this signature. It says Sliver implants embed several pieces of self managed cryptographic material at compile time: the server age public key, the implant peer age public key, the implant peer age private key, a minisign signature of the implant age peer public key, and the server minisign public key.[^2] These are not one universal static key set shared by all Sliver operators. They are generated and packaged into Sliver implants at build time.

That build time packaging matters for attribution of the network pattern. The rule is not matching a random string that happened to appear in one exercise. It is matching a visible part of the key trust material that Sliver itself can generate and place into implants when they are built. That strengthens the connection between the observed age plus minisign pattern and Sliver style implant or pivot behavior, while still leaving room for legitimate age and minisign use in other software.

Those pieces have different jobs. An age key pair is a public and private key pair from the age encryption system. In this context, the public age key can be sent to a peer and used by that peer to encrypt a newly generated secret, while only the holder of the matching private age key can decrypt it. That makes the age public key useful as bootstrap material. It is not the long lived bulk traffic cipher, but it lets peers establish a fresh symmetric session key before the main encrypted message stream begins.

Minisign is not the traffic encryption layer. Minisign is used to authenticate the age public key by proving that the key was signed by the Sliver server minisign private key. After the peers establish a session key, Sliver documents later message encryption as symmetric encryption with ChaCha20 Poly1305.[^2]

For implant to implant pivot key exchange, the initiator sends its age public key and the minisign signature of that public key as the first visible trust material. The listener verifies the minisign signature using the server minisign public key. If that check passes, the listener can trust the initiator age public key, generate a random session key, and encrypt that session key to the initiator age public key. The listener then sends back its own age public key, the minisign signature of its public key, and the encrypted session key. The initiator performs the same signature check, decrypts the session key with its age private key, and the two peers then use the session key for encrypted messages.[^2]

A public Sliver compatible C++ implant repository shows the same general theme from an implementation view. Its README tells the reader to generate a Sliver executable and retrieve key material from `implant.go`; the example includes an implant public key signature with the literal minisign text markers `untrusted comment:` and `trusted comment:`, plus a minisign server public key.[^3]

This rule is therefore not trying to identify Sliver from only one string, and it is not claiming that minisign encrypts traffic. The hunting value is the close combination of age style public key material and minisign signature comment material in the same internal stream. That combination lines up with the key authentication phase that can occur before later encrypted implant or pivot traffic. Because Sliver generates and embeds this age and minisign material into implants at build time, this key authentication pattern is a natural default for operators using Sliver built in transport and pivot mechanisms. The rule therefore hunts for framework provided cryptographic bootstrap material rather than an exercise specific string.

## Detection design

The rule is scoped HOME_NET to HOME_NET on purpose.

The main use case is internal post compromise or pivot traffic, not normal internet egress. In an IT to OT compromise path, operators often need to land on an IT or engineering workstation first, then pivot into a more restricted subnet. Sliver pivot documentation describes this pattern in general terms: an implant in a less restricted subnet can carry traffic for an implant in a restricted subnet.[^1]

The rule does not require a public CA, TLS certificate, SNI, JA3, or JA4. That is intentional. The Sliver transport documentation describes a self managed trust model: age keys are used to protect the session key, minisign signatures authenticate the age public keys, and the established session key is then used by the implant protocol for encrypted messages rather than relying on ordinary CA backed TLS.[^2]

The rule should be treated as HUNTING rather than TROJAN certainty because age and minisign are both legitimate technologies. A match does not prove Sliver by itself and does not prove malicious activity without supporting context.

## Proposed rule

Temporary SID is used here and should be replaced before publication.

```suricata
alert tcp $HOME_NET any -> $HOME_NET any (msg:"ET HUNTING Possible Sliver Age and Minisign Key Material in Internal TCP Stream"; flow:established; content:"|0A 3E 61 67 65 31|"; depth:64; content:"untrusted comment:"; distance:0; within:160; content:"trusted comment:"; distance:0; within:320; reference:url,sliver.sh/docs?name=Transport+Encryption; reference:url,github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Pivots.md; classtype:policy-violation; sid:9003122; rev:1; metadata:attack_target Client_Endpoint, deployment Internal, confidence Medium, signature_severity Medium, tag Sliver, tag Pivot, tag Hunting, created_at 2026_06_09;)
```

## Rule logic

The first content match anchors on a newline followed by `>age1`:

```text
|0A 3E 61 67 65 31|
```

That pattern is intended to match age public key style material as it appeared in the observed stream, while avoiding a loose bare `age1` match anywhere in payload. In the Sliver pivot exchange described above, this kind of age public key material is the key that the peer uses during session key establishment. It is visible before the later encrypted message stream begins when the exchange is not itself wrapped by another encrypted transport.

The next two matches require nearby minisign signature text markers:

```text
untrusted comment:
trusted comment:
```

Those strings are not encryption by themselves. They are part of minisign signature text format. In the Sliver pivot exchange, the minisign signature is used to authenticate the age public key. Put another way: the age key is the object being trusted for key exchange, and minisign is the proof that the Sliver server signed that key. Once that trust check passes, the peers can establish a symmetric session key and use that key to encrypt later traffic.

The relative windows are intentionally narrow enough to require these artifacts to appear together, but not so narrow that the rule only matches one exact byte layout from the proof PCAP.

## Validation artifacts

The proof PCAP is an anonymized contiguous time window cut. It preserves packet timing, conversation shape, ports, protocol mix, surrounding traffic, and the detection relevant age and minisign bytes. Lab identifying network artifacts were deterministically rewritten: IP addresses, unicast MAC addresses, hostnames, and NetBIOS hostname encodings. Checksums and lengths were regenerated as needed to keep packets valid.

The cut was made as a contiguous time slice, not packet level pruning. It keeps surrounding traffic context and is not an alert only proof PCAP.

Cut details:

1. Packet count: 1,621
2. Capture span: about 14 minutes and 14 seconds
3. SHA256: `03b08b6a2c616b2ab3a98ae0d46cccdc0779b9f752fd98aa9cd6e2486e42ebd9`

## Validation results

The anonymized contiguous cut was tested with the proposed rule and representative existing Suricata event rules loaded:

1. SID 9003122: 4 alerts
2. SID 2210054, `SURICATA STREAM excessive retransmissions`: 0 alerts
3. SID 2221010, `SURICATA HTTP unable to match response to request`: 0 alerts

Observed proposed rule alert flow in the anonymized PCAP:

```text
10.77.0.2 port 65238 and 10.77.1.5 port 8000
```

Observed proposed rule alert times:

```text
June 4 2026 at 19:49:46 UTC
June 4 2026 at 19:52:46 UTC
June 4 2026 at 19:54:03 UTC
```

## Expected false positive profile

The most likely false positives are legitimate transfers or management sessions that expose age public keys and minisign signatures in cleartext, for example internal release tooling, package validation, appliance update workflows, developer activity, or copied key and signature files. Minisign is legitimate signing technology and should not be treated as malicious by itself.

HOME_NET to HOME_NET scoping is expected to reduce broad internet noise and focus the rule on internal pivot and relay candidates. Environments with legitimate age and minisign usage over internal cleartext TCP should tune by approved hosts, ports, or asset groups.

## Caveats

1. This is a hunting rule, not a standalone Sliver conviction.
2. The pattern is strongest when the matched stream also has suspicious context such as internal pivoting, unusual workstation to workstation traffic, OT adjacent access, or opaque high volume C2 like communication.
3. The rule depends on key and signature material being visible in the TCP stream. mTLS, WireGuard, or another encrypted transport may hide this material.
4. age and minisign are legitimate tools; analyst review is required.

## Closing note

The goal is to cover a reusable network visible artifact from Sliver style self managed implant or pivot key exchange without hard coding lab IPs, OT subnets, timestamps, or exercise specific filenames. The proposed HOME_NET to HOME_NET scope targets the internal portion of the intrusion path where pivot traffic is most useful to defenders and where public CA backed TLS indicators may not exist.

Feedback on the rule title, HOME_NET to HOME_NET scope, metadata, and the best way to word the Sliver versus legitimate age and minisign caveat would be welcome.

## References

[^1]: Bishop Fox Sliver documentation, `Pivots`. The page states that pivots route implant traffic through other implants, can be useful when a restricted subnet cannot route directly to the internet, and allow chained implant connections. https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Pivots.md

[^2]: Bishop Fox Sliver documentation, `Transport Encryption`. The page lists embedded age keys and minisign signatures, describes implant to implant pivot key exchange where peers send age public keys and minisign signatures, and states that later messages are encrypted with the established session key using ChaCha20 Poly1305. https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Transport%20Encryption.md

[^3]: MrAle98, `Sliver-CPPImplant2` README. The README describes a C++ implant compatible with a fork of Sliver C2, lists pivot commands as supported, and shows generated Sliver implant key material including minisign `untrusted comment:` and `trusted comment:` signature text. https://github.com/MrAle98/Sliver-CPPImplant2/blob/master/README.md
