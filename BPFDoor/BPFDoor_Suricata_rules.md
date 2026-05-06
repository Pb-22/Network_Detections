#### 1 & 2. Visible command marker rule (2 rules using xbits)
```suricata
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL BPFDoor inbound ICMP X: seed"; itype:8; content:"X:"; startswith; xbits:set,bpfdoor_icmp_x_seed,track ip_dst,expire 30; noalert; sid:99020011; rev:1;)

alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL BPFDoor possible ICMP reply after inbound X: seed"; itype:0; dsize:>0; xbits:isset,bpfdoor_icmp_x_seed,track ip_src; sid:99020012; rev:1;)
```


#### 3 & 4. Hardcoded sequence 1234 rule inbound and outbound
```suricata
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE BPFDoor ICMP Echo Reply (Inbound)"; itype:0; icmp_seq:1234; threshold: type threshold, track by_src, count 2, seconds 60; url,rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; sid:90020032; rev:2;)
```
```suricata
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE BPFDoor ICMP Echo Request (Outbound)"; itype:8; icmp_seq:1234; threshold: type threshold, track by_dst, count 2, seconds 60; url,rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; sid:90020031; rev:2;)
```


#### 4. BPFDoor ICMP 0x7255 Magic-Byte Wake-Up Artifact ( Bonus rule written from a 2022 article)
```suricata
alert icmp any any -> any any (msg:"LOCAL BPFDoor ICMP 0x7255 magic-byte wake-up artifact"; itype:8; icode:0; content:"|72 55|"; depth:2; reference:url,https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor; sid:9002101; rev:1;)
```
