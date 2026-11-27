# HTTP test PCAPs

These files are ready to download and replay. The Python generator remains in
../tests/generate_fixtures.py so the same bytes can be reproduced; it supplements
these PCAPs rather than replacing them.

## Start here

Open [the PE32 document case](pe-disguise-http-positive-pe32-document.pcap).
It should produce one PEFileDisguise::DocumentImageMismatch Notice with
filename report.pdf. The honest executable control should produce none.

From the repository root, with Zeek 9.0.1 available:

```sh
mkdir -p pe-disguise-replay
cd pe-disguise-replay
zeek -C -r ../pe-disguise/pcap/pe-disguise-http-positive-pe32-document.pcap ../pe-disguise/Zeek/main.zeek
```

Keep main.zeek, pe.zeek and filename.zeek together. Main loads the two helpers.
Inspect notice.log for the expected finding. See manifest.json for file hashes,
case IDs and expected results, and validation.json for the actual replay results.

## Use Try Zeek

1. Select Zeek 9.0.1 and paste the detection source into main.zeek.
2. Click Add File. Click the selected new tab again to rename it pe.zeek, then
   paste that helper's source.
3. Add another tab named filename.zeek and paste the filename helper.
4. Upload one of these PCAPs and click Run. All tabs participate in the same
   Zeek run; the @load statements resolve the matching helper filenames.
5. Open the Notice log for a positive case. A zero result is expected for the
   controls listed below.

The combined script can also be used by itself when available. Use either the
combined script or the three original files, rather than loading both forms.

The three original files were also verified together here:
https://try.zeek.org/#/tryzeek/saved/0a2917bb9b014a178579f023412ecc55

Upload the primary PCAP if no capture is selected.

## Provenance and expected outcomes

All 28 files are deterministic synthetic Ethernet, IPv4, TCP and HTTP fixtures.
They contain inert PE header models and documentation addresses. They are not
native software captures, vendor programs or malware. The models have no entry
point, executable section flags or instructions. The ZIP case contains only a
generated model. None of the payloads needs to be executed.

Every included PCAP was replayed with the accepted detector. The 9 positive
cases produced 9 Notices in total; the other 19 produced none. The files match
the generator's previously verified hashes, including valid IP/TCP checksums.

Positive cases should alert. Negative controls exercise content or names outside
the signal. Abstention controls exercise incomplete, ambiguous or unsupported
input. An abstention does not establish that the file is benign.

## Positive cases

| PCAP | What it checks | Frames | Expected Notices |
|---|---|---:|---:|
| [pe x86](pe-disguise-http-positive-pe32-document.pcap) | PE32 model advertised as a PDF. | 13 | 1 |
| [pe x64](pe-disguise-http-positive-pe64-image.pcap) | PE32+ x64 model advertised as an image. | 13 | 1 |
| [pe arm64](pe-disguise-http-positive-arm64-image.pcap) | ARM64 model advertised as an image. | 13 | 1 |
| [extended empty](pe-disguise-http-positive-extended-name-empty-fallback.pcap) | Valid filename* overrides an empty fallback. | 13 | 1 |
| [extended path](pe-disguise-http-positive-extended-name-path-fallback.pcap) | Valid filename* overrides a fallback containing a path. | 13 | 1 |
| [extended legacy](pe-disguise-http-positive-extended-name-legacy-fallback.pcap) | Valid UTF-8 filename* overrides legacy fallback bytes. | 13 | 1 |
| [extended reverse](pe-disguise-http-positive-extended-name-reverse-order.pcap) | The selected extended name works in either parameter order. | 13 | 1 |
| [identity encoding](pe-disguise-http-positive-explicit-identity-encoding.pcap) | Explicit identity encoding remains eligible. | 13 | 1 |
| [long overlay](pe-disguise-http-positive-large-overlay.pcap) | A PE model with a 1 MiB inert overlay. | 2061 | 1 |

## Negative controls

| PCAP | What it checks | Frames | Expected Notices |
|---|---|---:|---:|
| [bad pe signature](pe-disguise-http-negative-bad-pe-signature.pcap) | Reject an invalid PE signature. | 13 | 0 |
| [raw section past eof](pe-disguise-http-negative-raw-section-past-eof.pcap) | Reject a raw section extending beyond the object. | 13 | 0 |
| [honest exe](pe-disguise-http-negative-honest-executable-name.pcap) | An honest executable filename stays outside the signal. | 13 | 0 |
| [honest dll](pe-disguise-http-negative-honest-dll-name.pcap) | An honest DLL filename stays outside the signal. | 13 | 0 |
| [outer zip](pe-disguise-http-negative-outer-zip-with-pe-model.pcap) | The outer ZIP contains an inert PE model. | 15 | 0 |
| [non pe data](pe-disguise-http-negative-ordinary-data.pcap) | Ordinary data advertised as a document. | 15 | 0 |
| [content type name poison](pe-disguise-http-negative-content-type-name-poison.pcap) | Content-Type cannot replace an honest executable name. | 13 | 0 |

## Expected abstentions

| PCAP | What it checks | Frames | Expected Notices |
|---|---|---:|---:|
| [invalid active utf8](pe-disguise-http-abstain-invalid-active-utf8.pcap) | Skip invalid UTF-8 in the selected extended name. | 13 | 0 |
| [invalid active language](pe-disguise-http-abstain-invalid-active-language.pcap) | Skip malformed language syntax in the selected name. | 13 | 0 |
| [duplicate parameter](pe-disguise-http-abstain-duplicate-parameter.pcap) | Skip a duplicate filename parameter. | 13 | 0 |
| [path selected](pe-disguise-http-abstain-path-selected.pcap) | Skip an unsafe selected path. | 13 | 0 |
| [unsupported charset](pe-disguise-http-abstain-unsupported-charset.pcap) | Skip an unsupported selected charset. | 13 | 0 |
| [unknown disposition](pe-disguise-http-abstain-unknown-disposition.pcap) | Skip an unsupported disposition. | 13 | 0 |
| [short body vs content length](pe-disguise-http-abstain-short-body-vs-content-length.pcap) | Skip a body shorter than Content-Length. | 13 | 0 |
| [range response](pe-disguise-http-abstain-range-response.pcap) | Skip a range response. | 13 | 0 |
| [chunked](pe-disguise-http-abstain-chunked.pcap) | Skip transfer coding outside the supported profile. | 15 | 0 |
| [uri only](pe-disguise-http-abstain-uri-only.pcap) | A document name in the URI alone does not qualify. | 13 | 0 |
| [duplicate disposition](pe-disguise-http-abstain-duplicate-disposition.pcap) | Skip duplicate Content-Disposition fields. | 13 | 0 |
| [duplicate content length](pe-disguise-http-abstain-duplicate-content-length.pcap) | Skip duplicate Content-Length fields. | 13 | 0 |
