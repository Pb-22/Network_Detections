# Cloudflare Suspicious File Delivery

This directory contains detection engineering artifacts related to suspicious file delivery through Cloudflare hosting surfaces.

## Try a PCAP first

Download [scenario 6](scenario6_zeek_test_%20also_triggers_Suricata2068664.pcap) and replay it with the included Zeek script on stock Zeek 9.0.1. The current source produces two `CLOUDFLARE_STAGE::Suspicious_Download_After_Cloudflare_Domain` Notices. Open the PCAP in Wireshark before running any reproduction tool if you prefer.

[Scenario 8](scenario8_fires%20all_4_Suricata.pcap) is a Suricata case and produces zero Notices with this Zeek script. That result does not establish that its content is benign. These are the existing public test captures; their packet bytes have not been rewritten. Optional generation and regression tools remain secondary to the ready files.

The [reader notes](../website-notes/Cloudflare-Suspicious-File-Delivery/cloudflare_file_1.0.0.json) accompany the source and explain the hostname context, response checks and exact Notice arguments.

The current focus is on HTTP requests to Cloudflare family hostnames such as:

- `*.trycloudflare.com`
- `*.pages.dev`
- `*.workers.dev`
- `*.r2.dev`

where the requested URI ends in a potentially suspicious scriptable or launcher-oriented extension, including:

- `.wsf`
- `.py`
- `.js`
- `.jse`
- `.vbs`
- `.vbe`
- `.bat`
- `.cmd`
- `.ps1`
- `.hta`
- `.url`

## Purpose

These materials were developed to explore detection opportunities for suspicious file delivery over Cloudflare-hosted infrastructure, especially where the request path suggests direct download of scriptable payloads or launcher-type content.

This folder may include:

- Suricata rules
- testing notes
- PCAPs
- tuning notes
- examples of URI patterns and edge cases
- references to public reporting and Cloudflare documentation

## Rule-writing notes

A key design question in this work was how to detect targeted file extensions in URIs while still handling normal query-string or fragment variations such as:

- `/payload.wsf`
- `/payload.wsf?ref=mail`
- `/dropper.js#section`

An initial PCRE approach was tested locally, followed by Emerging Threats reviewer feedback recommending a more performance-conscious Suricata style using a cheap `content:"."` anchor before a relative `pcre`.

That exchange is important context for this work:
- local proof-of-concept matching may be broader
- ET-style submission may prefer narrower, more performance-aware anchored logic
- separate per-domain rules may be preferable to a single broad combined rule

## References

- Cofense reporting on abuse of Cloudflare services for credential theft and malware delivery
- Cloudflare documentation for relevant hosting/tunnel services
- Emerging Threats community discussion and publication notes related to these rules
