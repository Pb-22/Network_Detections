# Sliver Pivot Minisign Suricata Signatures

## Possible Sliver Age and Minisign Key Material in Internal TCP Stream

This hunting rule looks for age style public key material followed by minisign signature markers in an internal TCP stream. It is intended for HOME_NET to HOME_NET hunting where Sliver style implant or pivot key authentication material may be visible before later encrypted traffic begins.

```suricata
alert tcp $HOME_NET any -> $HOME_NET any (msg:"ET HUNTING Possible Sliver Age and Minisign Key Material in Internal TCP Stream"; flow:established; content:"|0A 3E 61 67 65 31|"; depth:64; content:"untrusted comment:"; distance:0; within:160; content:"trusted comment:"; distance:0; within:320; reference:url,sliver.sh/docs?name=Transport+Encryption; reference:url,github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Pivots.md; classtype:policy-violation; sid:9003122; rev:1; metadata:attack_target Client_Endpoint, deployment Internal, confidence Medium, signature_severity Medium, tag Sliver, tag Pivot, tag Hunting, created_at 2026_06_09;)
```

## Notes

1. Temporary SID `9003122` should be replaced before publication in a shared ruleset.
2. Treat matches as hunting leads, not standalone proof of Sliver or malicious activity.
3. age and minisign are legitimate tools; tune by known good hosts, ports, or internal update and release systems where needed.
4. The rule intentionally uses HOME_NET to HOME_NET to focus on internal pivot and relay candidates.
