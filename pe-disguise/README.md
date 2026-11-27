# PE content advertised as a document or image

This Zeek detector reports a complete HTTP download when its selected Content-Disposition filename claims a document or image but its outer bytes contain coherent PE structure. It emits PEFileDisguise::DocumentImageMismatch in notice.log.

The finding identifies a file format and advertised-name mismatch. It does not establish maliciousness or execution.

## Layout

- Zeek/main.zeek: HTTP/file association, completion checks and Notice emission.
- Zeek/filename.zeek: bounded Content-Disposition, UTF-8 and language-tag parsing.
- Zeek/pe.zeek: bounded PE32/PE32+ structure checks.
- tests/: portable fixture generation, replay checks and resource/coexistence observers.

Keep the three Zeek files together. The runtime does not read test fixtures or use vendor, address or payload-hash allowlists.

## Replay a capture

With stock Zeek 9.0.1 available, run this from the repository root:

```sh
mkdir -p pe-disguise-replay
cd pe-disguise-replay
zeek -C -r /path/to/sample.pcap ../pe-disguise/Zeek/main.zeek
```

Replace /path/to/sample.pcap with the capture path. Zeek writes logs in the working directory. The script loads its adjacent helpers and HTTP/Notice dependencies. It also works with bare startup and explicit dependencies; it does not require native PE analysis or a hashing policy. Existing policies remain enabled.

The Notice message is:

```text
PE content advertised with a document or image filename
```

Native UID, FUID and connection fields bind the finding to its response file. src is the downloader client and dst is the HTTP server; the file bytes travel from responder to originator. The sub field includes filename_hex, filename_source, format, observed_bytes, declared_bytes and ports. Hex preserves selected filename bytes without making punctuation look like extra evidence fields.

## Run the focused tests

The public test runner generates inert, modeled HTTP/TCP fixtures locally and replays them through the exact included source. Generated fixtures are synthetic test inputs, not captures of software running or a native Windows/browser workflow. No vendor binaries, downloaded specimens or private captures are included.

The runner uses Python standard libraries and a pinned Docker image:

```sh
docker pull zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
python3 pe-disguise/tests/run-tests.py --output ../pe-disguise-test-output
```

Run --help for the supported options. Keep replay output outside the source directories. Container replays have no network, a read-only root and bounded resources. The tests validate positive and negative findings, filename selection, file/transaction evidence, incomplete-body abstention and analyzer coexistence. The public focused suite is distinct from broader private artifact evaluations.

The checked public suite contains 28 synthetic HTTP cases with 9 expected Notices, plus 8 filename probes. Both standard-library unit tests and the full pinned-engine replay pass. See validation.json for the source identities, fixture hashes and actual per-case results.

The optional tests/measure-engine.py helper records one engine child's CPU, wall time and Linux peak RSS per fresh wrapper. Use it inside a Linux container, not around docker run. It does not prove live throughput or a production false positive rate. No benchmark or raw runtime output is committed by default.

## Supported signal

The first profile requires:

- One top-level responder file from a status 200 HTTP response.
- One valid meaningful Content-Disposition filename using attachment or inline. A valid UTF-8 filename* wins over an unused plain fallback, regardless of parameter order. Plain names support ASCII or well-formed UTF-8; other unlabelled legacy octets abstain. Optional language syntax follows RFC 5646 without a registry lookup.
- A final ASCII document/image suffix: pdf, doc, docx, xls, xlsx, ppt, pptx, rtf, odt, ods, odp, jpg, jpeg, png, gif, bmp, tif, tiff, webp or svg.
- Identity encoding, one valid Content-Length, complete observed bytes and clean native file/HTTP completion.
- Exact MZ/NT signatures, a supported machine/magic pairing, bounded coherent optional/header/section tables and section raw spans inside the complete object. I386, AMD64 and ARM64 are supported. Legitimate overlays are allowed.

The byte checks indicate PE structure; they are not a Windows loader, disassembler or Authenticode validator. Ordinary executable/DLL/CPL and generic binary names do not qualify. An outer ZIP containing PE stays outside the signal. URI-only names and Content-Type name do not override the selected response filename.

## Bounds and known misses

Fixed source limits are 64 KiB prefix per file, 128 active contexts, 4 KiB header values, 255 filename bytes, 16 parameters, 96 sections and 256 MiB declared object length. They are source constants, not promised command-line redefinition options.

Ambiguous/invalid metadata, unqualified decoding, transfer encodings, ranges, multipart bodies, incomplete visibility and objects outside those bounds abstain. At saturation, additional eligible files can be skipped; admission_drops in the exported health record counts those decisions. A 129-flow test with the 128-context cap intentionally skips one file. These are explicit coverage limits, not zero false-negative guarantees.

Encrypted traffic without visible HTTP bodies is outside the detector. Stock Zeek 9.0.1 is the verified runtime; other Zeek releases and vendor builds, including Corelight, require their own compatibility and visibility checks. Native Windows Update/updater behavior and production selectivity have not been qualified.

## Resource behavior

The detector copies only the required DOS, COFF, optional-header and section-table prefix extents. Once classification is resolved, it removes only its exact DATA_EVENT callback instance. Separate stream and chunk consumers remain attached and receive full data. Already queued callbacks can still arrive. Positive Notices still wait for both file and HTTP completion.

Terminal timeout/gap/overflow rejection releases owned budgets immediately and idempotently. Health counters describe this detector's owned state, not total Zeek or other policy memory. Reduced callback work and smaller prefix buffers should not be read as an equal percentage reduction in whole-process RSS.

## References

- [PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Content-Disposition, RFC 6266](https://www.rfc-editor.org/rfc/rfc6266.html)
- [Extended parameter encoding, RFC 8187](https://www.rfc-editor.org/rfc/rfc8187.html)
- [Language tag syntax, RFC 5646](https://www.rfc-editor.org/rfc/rfc5646.html)
