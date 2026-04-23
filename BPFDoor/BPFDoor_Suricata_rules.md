#### 1. Visible command marker rule

```alert icmp any any -> any any (msg:"LOCAL BPFDoor-inspired ICMP visible X marker request"; itype:8; icode:0; content:"X:"; depth:2; reference:url,https://www.rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; sid:9002001; rev:2;)```

#### 2. Heartbeat / invalid code rule
```alert icmp any any -> any any (msg:"LOCAL BPFDoor-inspired ICMP invalid echo code 1 heartbeat"; itype:8; icode:1; reference:url,https://www.rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; sid:9002002; rev:3;)```


#### 3. Hardcoded sequence 1234 rule
```alert icmp any any -> any any (msg:"LOCAL BPFDoor-inspired ICMP hardcoded sequence 1234"; itype:8; icode:0; dsize:>0; icmp_seq:1234; reference:url,https://www.rapid7.com/blog/post/tr-new-whitepaper-stealthy-bpfdoor-variants/; sid:9002003; rev:1;)```

#### 4. BPFDoor ICMP 0x7255 Magic-Byte Wake-Up Artifact ( Bonus rule written from a 2022 article)
```alert icmp any any -> any any (msg:"LOCAL BPFDoor ICMP 0x7255 magic-byte wake-up artifact"; itype:8; icode:0; content:"|72 55|"; depth:2; reference:url,https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor; sid:9002101; rev:1;)```
