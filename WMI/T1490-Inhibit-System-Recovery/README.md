# T1490 — Inhibit System Recovery

This package describes a WMI-style command request that combines deletion of recovery data with explicit recovery disabling. The [complete rule file](Suricata/README.md) contains the signature, matching conditions, replay results, triage guidance and reference footnotes.

| Directory | Contents |
| --- | --- |
| [Suricata](Suricata/) | Complete Markdown rule file, directly loadable signature, wrapped HTML view and replay results |
| [pcaps](pcaps/) | Forty-one positive/negative captures, construction notes and case index |

The signature selects both actions in the same command value. Suricata 8.0.8 produced one alert on each of sixteen positive cases. Twenty-four negatives remained quiet; the wrong-interface negative also produced one alert. The detection guide explains the request-pattern and interface visibility boundaries.

Reference: [MITRE ATT&CK: Inhibit System Recovery (T1490)](https://attack.mitre.org/techniques/T1490/).
