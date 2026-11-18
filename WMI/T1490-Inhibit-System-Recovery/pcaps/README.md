# T1490 — Inhibit System Recovery: WMI Test Captures

These forty-one captures exercise a WMI-style command request combining deletion of recovery data with explicit recovery disabling. The matrix contains sixteen positive cases and twenty-five negative controls.

P means the combined-request detector should alert. N means it should remain quiet. These labels describe the detector's intended behavior, independently of whether an operator is authorized.

## Results

Suricata 8.0.8 produced one alert on each positive. Twenty-four negatives remained quiet; the wrong-interface control also produced one alert. The raw-stream rule recognizes the request pattern without authoritative negotiated-interface/context binding.

The [replayed rule](../Suricata/README.md) is SID `9955010`, revision `7`, with this message:

> HUNTING WMI-style combined recovery-inhibition command request

| Case | Type | Capture | Expected alerts | Observed alerts |
| --- | --- | --- | ---: | ---: |
| combined-vss-bcd | P | [combined-vss-bcd.pcap](combined-vss-bcd.pcap) | 1 | 1 |
| combined-wmic-bcd | P | [combined-wmic-bcd.pcap](combined-wmic-bcd.pcap) | 1 | 1 |
| combined-catalog-bcd | P | [combined-catalog-bcd.pcap](combined-catalog-bcd.pcap) | 1 | 1 |
| reversed-actions | P | [reversed-actions.pcap](reversed-actions.pcap) | 1 | 1 |
| and-and | P | [and-and.pcap](and-and.pcap) | 1 | 1 |
| case-variation | P | [case-variation.pcap](case-variation.pcap) | 1 | 1 |
| extra-whitespace | P | [extra-whitespace.pcap](extra-whitespace.pcap) | 1 | 1 |
| no-exe-suffix | P | [no-exe-suffix.pcap](no-exe-suffix.pcap) | 1 | 1 |
| system32-paths | P | [system32-paths.pcap](system32-paths.pcap) | 1 | 1 |
| native-output-wrapper | P | [native-output-wrapper.pcap](native-output-wrapper.pcap) | 1 | 1 |
| segmented-512 | P | [segmented-512.pcap](segmented-512.pcap) | 1 | 1 |
| segmented-96 | P | [segmented-96.pcap](segmented-96.pcap) | 1 | 1 |
| segmented-17 | P | [segmented-17.pcap](segmented-17.pcap) | 1 | 1 |
| coalesced-two-positives | P | [coalesced-two-positives.pcap](coalesced-two-positives.pcap) | 1 | 1 |
| coalesced-positive-then-benign | P | [coalesced-positive-then-benign.pcap](coalesced-positive-then-benign.pcap) | 1 | 1 |
| coalesced-single-actions-then-positive | P | [coalesced-single-actions-then-positive.pcap](coalesced-single-actions-then-positive.pcap) | 1 | 1 |
| deletion-only | N | [deletion-only.pcap](deletion-only.pcap) | 0 | 0 |
| wmic-deletion-only | N | [wmic-deletion-only.pcap](wmic-deletion-only.pcap) | 0 | 0 |
| catalog-only | N | [catalog-only.pcap](catalog-only.pcap) | 0 | 0 |
| recovery-only | N | [recovery-only.pcap](recovery-only.pcap) | 0 | 0 |
| list-shadows | N | [list-shadows.pcap](list-shadows.pcap) | 0 | 0 |
| oldest-only | N | [oldest-only.pcap](oldest-only.pcap) | 0 | 0 |
| recovery-query | N | [recovery-query.pcap](recovery-query.pcap) | 0 | 0 |
| enable-recovery | N | [enable-recovery.pcap](enable-recovery.pcap) | 0 | 0 |
| echo-both | N | [echo-both.pcap](echo-both.pcap) | 0 | 0 |
| comment-both | N | [comment-both.pcap](comment-both.pcap) | 0 | 0 |
| echo-second | N | [echo-second.pcap](echo-second.pcap) | 0 | 0 |
| comment-second | N | [comment-second.pcap](comment-second.pcap) | 0 | 0 |
| fake-executable | N | [fake-executable.pcap](fake-executable.pcap) | 0 | 0 |
| fake-recovery-value | N | [fake-recovery-value.pcap](fake-recovery-value.pcap) | 0 | 0 |
| description-text | N | [description-text.pcap](description-text.pcap) | 0 | 0 |
| split-actions-across-requests | N | [split-actions-across-requests.pcap](split-actions-across-requests.pcap) | 0 | 0 |
| split-reversed-actions | N | [split-reversed-actions.pcap](split-reversed-actions.pcap) | 0 | 0 |
| wrong-interface | N | [wrong-interface.pcap](wrong-interface.pcap) | 0 | 1 |
| wrong-opnum | N | [wrong-opnum.pcap](wrong-opnum.pcap) | 0 | 0 |
| wrong-class | N | [wrong-class.pcap](wrong-class.pcap) | 0 | 0 |
| wrong-method | N | [wrong-method.pcap](wrong-method.pcap) | 0 | 0 |
| wrong-direction | N | [wrong-direction.pcap](wrong-direction.pcap) | 0 | 0 |
| original-authorized-whoami | N | [original-authorized-whoami.pcap](original-authorized-whoami.pcap) | 0 | 0 |
| original-readonly-query | N | [original-readonly-query.pcap](original-readonly-query.pcap) | 0 | 0 |
| original-sealed-control | N | [original-sealed-control.pcap](original-sealed-control.pcap) | 0 | 0 |

## Construction and scope

The combined commands and boundary cases are offline derivatives of the controlled WMI execution capture. Command substitutions preserve serialized field lengths; IPv4/TCP checksums are recomputed. Modified RPC/NTLM authentication signatures are not recomputed. Coalesced conversations have distinct modeled call IDs. TCP segmentation variants preserve the constructed stream bytes.

The original authorized execution, read-only query, and sealed native control retain their original capture bytes. The sealed control measures visibility: its arguments are encrypted. All captures are for offline replay; no destructive recovery command was executed to produce these test cases.

[cases.json](cases.json) records each capture's role, hash, packet count, provenance and expected/observed outcome. [SHA256SUMS](../SHA256SUMS) records the technique package's file hashes.

Reference: [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/).
