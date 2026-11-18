# PKINIT and Linked Self-Targeted Kerberos U2U

The maintained Zeek detector, package loader, replay runner and tests have moved to [Pb-22/zeek-detections](https://github.com/Pb-22/zeek-detections). The detector source bytes are unchanged by the move.

- [Current detector](https://github.com/Pb-22/zeek-detections/blob/main/scripts/pkinit-u2u.zeek)
- [Detection logic, parser compatibility and triage](https://github.com/Pb-22/zeek-detections/blob/main/DETECTOR-GUIDE.md)
- [Installation and publisher-selected modules](https://github.com/Pb-22/zeek-detections#install)
- [Replay cases and measured results](https://github.com/Pb-22/zeek-detections/blob/main/validation.json)
- [Original package before relocation](https://github.com/Pb-22/Network_Detections/tree/5da4490f5f5210e8b75e46fe1a6ee1f7afb8c6f4/Certipy/PKINIT-U2U)

## Packet evidence

The eight [captures](pcap/) and [packet guide](PACKET-GUIDE.md) remain here with their original packet bytes. Seven captures are authentic lab exchanges; the eighth is a derived partial-view positive with an expected missing-precursor detection loss. Copies in the dedicated Zeek repository make its offline test suite self-contained.

The analytic recognizes successful PKINIT followed by linked, same-account, self-targeted U2U ticket issuance. It identifies UnPAC-compatible ticket activity, not proof of NT-hash extraction. The dedicated package retains the Zeek 9.0.0 parser notes, worker-placement requirements, account-only notice subject and separate constructed event regressions.

Use the new repository for installation and replay. Do not load both an older standalone copy and the new package. [SHA256SUMS](SHA256SUMS) binds the retained files in this directory.
