# Cloudflare Suspicious File Delivery

This directory contains detection engineering artifacts related to suspicious file delivery through Cloudflare-managed hosting surfaces.

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
