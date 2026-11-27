# Focused synthetic tests

These tests construct **inert PE header models** and wrap them in deterministic,
checksum-correct **synthetic Ethernet/IPv4/TCP/HTTP PCAPs**. They are not native
captures, loader-valid programs, malware specimens, or vendor fixtures. The
models contain no entry point, executable section flags, instructions, or DOS
stub. The ZIP control contains only a generated model named `report.pdf`.
Nothing is downloaded by the test scripts.

## Run

Requirements: Python 3 standard library, Docker, and the exact Zeek 9.0.1 image
already present locally. Provision that image explicitly if needed:

```sh
docker pull zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
```

From the repository root (quote paths containing spaces):

```sh
python3 pe-disguise/tests/run-tests.py --help
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s pe-disguise/tests -p test_harness.py -v
python3 pe-disguise/tests/run-tests.py --output '/absolute/path/outside/repository/fresh test results'
```

The output directory **must not exist** and must be outside the repository.
The runner resolves source paths relative to its own location; the current
working directory and checkout name do not matter. Docker runs with the host
UID/GID, `--pull=never`, `--network=none`, a read-only root filesystem, no
capabilities, no-new-privileges, a read-only package mount, and only the explicit
results mount writable. It needs no packet-capture privileges or `NET_RAW`.
No packages or images are installed automatically. Engine invocations time out
after 120 seconds each.

An installed Zeek can be selected with `--zeek /path/to/zeek`; the pinned Docker
image is the reproducible reference environment. The runner loads the exact
public `Zeek/main.zeek`, which loads `pe.zeek` and then `filename.zeek`; it never
replaces those policy files. `base/protocols/conn` is loaded for identity checks.
All observer scripts are **test only**, not deployment dependencies.

Generate PCAPs without replaying them:

```sh
python3 pe-disguise/tests/generate_fixtures.py --output '/absolute/path/outside/repository/fresh fixtures'
```

## Coverage and assertions

There are **28 HTTP cases**, with **9 expected Notices**, and **8 primitive
filename-precedence probes**. The runner requires exact aggregate counts.

- PE32 x86, PE32+ x64 and ARM64 header-model positives.
- Extended `filename*` selection over empty, path-shaped and unsupported legacy
  fallback bytes, plus reverse parameter order.
- Active invalid UTF-8/language, duplicate parameters, selected paths,
  unsupported charset and unknown disposition abstentions.
- Bad PE signature, raw section past EOF, honest `.exe`/`.dll` filename controls,
  an outer ZIP containing a model named `.pdf`, and non-PE data.
- Short response versus Content-Length, range response, chunked transfer,
  Content-Type filename poisoning, URI-only naming, duplicate disposition and
  duplicate Content-Length controls; explicit identity encoding positive.
- A 1 MiB inert overlay positive exercises prefix-only parsing and analyzer
  detachment while independent STREAM and CHUNK companions continue receiving
  the entire object.

For every case the runner checks the real Zeek HTTP/connection/file records,
UID/FUID linkage, reserved peers and ports, HTTP and file byte counts, exact
Notice cardinality, and zero final active contexts, retained prefix bytes and
admission drops. Positive Notices require exact parsed evidence fields
(filename hex, format, observed/declared bytes, peers, UID and FUID), complete
file length, zero missing/overflow bytes, no file timeout, the exact Notice message, and a timestamp no earlier than the final response-body packet and
no later than capture end. Both companions must receive every modeled object
byte with matching FUIDs; CHUNK offsets must be contiguous.

The long-overlay case additionally requires at most four detector callbacks,
callback bytes below one eighth of the body, exactly 416 peak retained prefix
bytes, and at least 100 callbacks in each unaffected companion. All cases cap
peak retained prefix at 432 bytes, the largest generated header table.
`test_harness.py` independently checks model construction, deterministic PCAP
bytes, IP/TCP checksums, the three-way handshake and two-sided FIN teardown.
Packet timestamps are fixed; endpoints are reserved documentation addresses.

`summary.json`, `commands.json`, fixture hashes, actual engine stdout/stderr,
PCAPs and logs are written only beneath the requested output directory. The
summary binds the exercised runtime source hashes. A failed run exits nonzero
and retains its partial evidence; rerun into a different fresh directory.

## Scope limits

This compact suite is not a publication of a larger private battery, and is not
an independent proof of PE loader validity or arbitrary real-network behavior.
The detection profile targets the first outer HTTP response file, status 200,
identity representation, one Content-Length and Content-Disposition, with no
range, transfer coding or multipart. Unsupported/ambiguous metadata is an
abstention, not evidence that content is benign. The modeled filename and PE
header cases exercise selected policy constraints, not complete RFC or PE/COFF
conformance. They do not cover TLS decryption, packet loss, adversarial TCP
reassembly, arbitrary concurrency, MIME nesting or every resource limit.

Relevant format references: [PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[RFC 6266](https://www.rfc-editor.org/rfc/rfc6266),
[RFC 8187](https://www.rfc-editor.org/rfc/rfc8187), and
[RFC 5646](https://www.rfc-editor.org/rfc/rfc5646).
