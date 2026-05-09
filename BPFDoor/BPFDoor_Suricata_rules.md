### These first 2 need to be used together
#### 1. ET MALWARE BPFDoor ICMP Echo Request, X:[COMMAND] (Inbound)
```suricata

alert icmp any any -> $HOME_NET any (msg:"ET MALWARE BPFDoor ICMP Echo Request, X:[COMMAND] (Inbound)"; xbits:set,ET.bpfdoor,track ip_dst,expire 60; noalert; itype:8; content:"X:"; startswith; reference:url,rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; reference:url,community.emergingthreats.net/t/sig-bpfdoor-icmpshell-icmp-artifacts-from-rapid7-whitepaper/3271; classtype:trojan-activity; sid:2069175; rev:3; metadata:affected_product Linux, attack_target Client_Endpoint, created_at 2026_05_05, deployment Perimeter, malware_family BPFDoor, confidence High, signature_severity Critical, tag BPF, updated_at 2026_05_08; target:dest_ip;)

```
#### 2. ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)
```suricata
alert icmp $HOME_NET any -> any any (msg:"ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)"; xbits:isset,ET.bpfdoor,track ip_src; itype:0; reference:url,rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; reference:url,community.emergingthreats.net/t/sig-bpfdoor-icmpshell-icmp-artifacts-from-rapid7-whitepaper/3271; classtype:trojan-activity; sid:2069174; rev:3; metadata:affected_product Linux, attack_target Client_Endpoint, created_at 2026_05_05, deployment Perimeter, malware_family BPFDoor, confidence High, signature_severity Critical, tag BPF, updated_at 2026_05_08; target:src_ip;)
```
---------
#### 3. ET MALWARE BPFDoor ICMP Echo Reply
```suricata
alert icmp $HOME_NET any -> any any (msg:"ET MALWARE BPFDoor ICMP Echo Reply"; itype:0; icmp_seq:1234; threshold:type threshold, track by_src, count 10, seconds 60; reference:url,rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; reference:url,community.emergingthreats.net/t/sig-bpfdoor-icmpshell-icmp-artifacts-from-rapid7-whitepaper/3271; classtype:trojan-activity; sid:2069173; rev:2; metadata:affected_product Linux, attack_target Client_Endpoint, created_at 2026_05_05, deployment Perimeter, deprecation_reason False_Positive, malware_family BPFDoor, performance_impact Moderate, confidence Low, signature_severity Major, tag BPF, updated_at 2026_05_08; target:dest_ip;)
```
---------

#### 5. BPFDoor ICMP 0x7255 Magic-Byte Wake-Up Artifact ( Bonus rule written from a 2022 article)
```suricata
alert icmp any any -> any any (msg:"LOCAL BPFDoor ICMP 0x7255 magic-byte wake-up artifact"; itype:8; icode:0; content:"|72 55|"; depth:2; reference:url,https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor; sid:9002101; rev:1;)
```
