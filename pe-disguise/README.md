# PE content advertised as a document or image

This Zeek detector reports a complete HTTP download when its selected Content-Disposition filename claims a document or image but its outer bytes contain coherent PE structure. It emits PEFileDisguise::DocumentImageMismatch in notice.log.

The finding means the file bytes and advertised filename do not agree. Treat it as a file delivery signal, not proof that malware ran.

## Layout

- Zeek/main.zeek: associates files with HTTP responses, checks completion and emits Notices.
- Zeek/filename.zeek: parses Content-Disposition, UTF-8 and language tags within fixed limits.
- Zeek/pe.zeek: bounded PE32/PE32+ structure checks.
- tests/: generates fixtures, runs replays and checks resource use and other analyzers.

Keep the three Zeek files together. The detector examines observed response headers and file bytes. It does not identify files through test fixtures or lists of vendors, addresses or payload hashes.

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

Run --help for the options and keep replay output outside the source directories. The containers have no network access and cannot write to their root filesystem. The tests check expected findings, filename selection, file and HTTP evidence, handling of incomplete bodies, and whether other analyzers still receive the data. Broader private artifact evaluations are separate from this public suite.

The public suite passes 28 synthetic HTTP cases with 9 expected Notices and 8 filename probes. The two Python unit tests also pass. See validation.json for the source hashes, fixture hashes and results for each case.

The optional tests/measure-engine.py helper records one engine child's CPU, wall time and Linux peak RSS per fresh wrapper. Use it inside a Linux container, not around docker run. It does not prove live throughput or a production false positive rate. No benchmark or raw runtime output is committed by default.

## Supported signal

The first profile requires:

- One outer responder file from a status 200 HTTP response.
- One valid Content-Disposition field with a usable filename, using attachment or inline. A valid UTF-8 filename* takes precedence over an unused plain fallback, regardless of parameter order. Plain names support ASCII or valid UTF-8; the detector skips other unlabelled legacy encodings. Optional language syntax follows RFC 5646 without a registry lookup.
- A final ASCII document/image suffix: pdf, doc, docx, xls, xlsx, ppt, pptx, rtf, odt, ods, odp, jpg, jpeg, png, gif, bmp, tif, tiff, webp or svg.
- Identity encoding, one valid Content-Length, complete observed bytes and clean native file/HTTP completion.
- Exact MZ/NT signatures, a supported machine/magic pairing, bounded coherent optional/header/section tables and section raw spans inside the complete object. I386, AMD64 and ARM64 are supported. Legitimate overlays are allowed.

The byte checks identify PE structure. They do not validate Windows loading, instructions or Authenticode signatures. Ordinary executable, DLL, CPL and generic binary names do not qualify. A ZIP containing PE also stays outside the signal. A filename in the URI or Content-Type name cannot replace the selected response filename.

## Bounds and known misses

Fixed source limits are 64 KiB prefix per file, 128 active contexts, 4 KiB header values, 255 filename bytes, 16 parameters, 96 sections and 256 MiB declared object length. Change these constants in the source rather than through CLI options.

The detector skips ambiguous or invalid metadata, unqualified decoding, transfer encodings, ranges, multipart bodies, incomplete objects and files outside those bounds. It can also skip eligible files when all contexts are occupied. The exported admission_drops counter records those decisions. In a capacity test with 129 eligible files at once, the 128 context limit caused one file to be skipped. These limits can cause missed detections.

Encrypted traffic without visible HTTP bodies is outside the detector. Stock Zeek 9.0.1 is the verified runtime; other Zeek releases and vendor builds, including Corelight, require their own compatibility and visibility checks. Native Windows Update/updater behavior and production selectivity have not been qualified.

## Resource behavior

The detector copies only the bytes needed for the DOS header, COFF header, optional header and section table. After it classifies the prefix, it removes only its own DATA_EVENT callback. Other stream and chunk consumers remain attached and receive the full data. Callbacks already in the queue can still arrive. Positive Notices wait for both file and HTTP completion.

A file timeout, gap or overflow causes the detector to release its state immediately. Later callbacks cannot release it twice. Health counters measure this detector's state, not all memory used by Zeek or other policies. Smaller buffers and fewer callbacks do not imply the same reduction in total process RSS.

## References

- [PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Content-Disposition, RFC 6266](https://www.rfc-editor.org/rfc/rfc6266.html)
- [Extended parameter encoding, RFC 8187](https://www.rfc-editor.org/rfc/rfc8187.html)
- [Language tag syntax, RFC 5646](https://www.rfc-editor.org/rfc/rfc5646.html)
