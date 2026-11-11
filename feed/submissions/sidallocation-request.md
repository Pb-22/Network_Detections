# Request: SID range allocation for the Pb-22 Open Suricata feed

I maintain the public Network_Detections repository and am establishing an independently maintained Suricata feed:

- Repository: https://github.com/Pb-22/Network_Detections
- Candidate feed: https://raw.githubusercontent.com/Pb-22/Network_Detections/main/feed/suricata/pb22.rules
- Feed documentation: https://github.com/Pb-22/Network_Detections/tree/main/feed
- License: BSD-3-Clause

The initial feed contains five rules backed by retained PCAP fixtures and Suricata 8 validation. It covers RedFlick DNSObserver HTTP registration, a Sliver age/minisign hunting pattern, and three CAV3RN DNS branch patterns. Rules already published by Emerging Threats are deliberately excluded to prevent duplicate ET SIDs.

The candidate currently uses temporary SIDs from the `1000000-1999999` local use range. That is appropriate for isolated testing but creates collision risk for subscribers who combine this feed with their own local rules.

I am requesting a modest dedicated allocation of 1,000 SIDs for the maintained public feed. I am happy to accept whatever starting point and block size the working group considers appropriate. After allocation I will renumber the feed, rerun syntax and replay validation, and publish the permanent SID map before asking OISF to list `pb22/open` in the Suricata Rule Index.

Thank you for maintaining the registry.
