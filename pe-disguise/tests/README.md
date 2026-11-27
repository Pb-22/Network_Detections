# Focused synthetic tests

The tests generate inert PE header models, place them in synthetic HTTP traffic
and replay the PCAPs through Zeek. Packet bytes are deterministic and have valid
IP and TCP checksums. The models contain no entry point, executable section
flags, instructions or DOS stub. The ZIP control contains only a generated
model named `report.pdf`. The scripts do not download specimens or vendor files.

## Run

Ready PCAPs are available in [pcap/](../pcap/), with expected results in its
README. Use them directly in Zeek or Try Zeek. The generator stays here to
reproduce the same bytes, while this runner exercises the full assertions.

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

Choose a new output directory outside the repository. The runner resolves
source paths relative to its own location, so the checkout name and working
directory do not matter. Docker uses the host UID/GID with `--pull=never` and
`--network=none`. It cannot write to the container root or package files, has no
capabilities and uses `no-new-privileges`. Only the results mount accepts writes.
The tests need no packet capture privileges or `NET_RAW`. They do not install
packages or images. Each engine invocation has a 120 second timeout.

An installed Zeek can be selected with `--zeek /path/to/zeek`; the pinned Docker
image is the reproducible reference environment. The runner loads the exact
public `Zeek/main.zeek`, which loads `pe.zeek` and then `filename.zeek`; it never
replaces those policy files. `base/protocols/conn` is loaded for identity checks.
The tests use the observer scripts; the detector runs without them.

Generate PCAPs without replaying them:

```sh
python3 pe-disguise/tests/generate_fixtures.py --output '/absolute/path/outside/repository/fresh fixtures'
```

## Coverage and assertions

The suite has 28 HTTP cases with 9 expected Notices and 8 filename probes.
The runner checks the exact counts.

- PE32 x86, PE32+ x64 and ARM64 header models that should produce Notices.
- Extended `filename*` selection over empty, path and unsupported legacy
  fallback bytes, plus reverse parameter order.
- Active invalid UTF-8/language, duplicate parameters, selected paths,
  unsupported charset and unknown disposition abstentions.
- Bad PE signature, raw section past EOF, honest `.exe`/`.dll` filename controls,
  an outer ZIP containing a model named `.pdf`, and data without PE headers.
- Short response versus Content-Length, range response, chunked transfer,
  Content-Type filename poisoning, names supplied only in the URI, duplicate disposition and
  duplicate Content-Length controls; explicit identity encoding positive.
- A model with a 1 MiB inert overlay checks that the detector reads the prefix
  and removes its own analyzer while the independent STREAM and CHUNK consumers
  still receive the entire object.

For every case the runner checks the real Zeek HTTP/connection/file records,
UID/FUID linkage, reserved peers and ports, HTTP and file byte counts, exact
Notice cardinality, and zero final active contexts, retained prefix bytes and
admission drops. Positive Notices require exact parsed evidence fields
(filename hex, format, observed/declared bytes, peers, UID and FUID), complete
file length, zero missing or overflow bytes, no file timeout, the exact Notice
message, and a timestamp no earlier than the final packet carrying response data and
no later than capture end. Both companions must receive every modeled object
byte with matching FUIDs; CHUNK offsets must be contiguous.

The `long-overlay` case also requires at most four detector callbacks,
callback bytes below one eighth of the body, exactly 416 peak retained prefix
bytes, and at least 100 callbacks in each unaffected companion. All cases cap
peak retained prefix at 432 bytes, the largest generated header table.
`test_harness.py` independently checks model construction, deterministic PCAP
bytes, IP/TCP checksums, the TCP handshake and FIN teardown from both peers.
Packet timestamps are fixed; endpoints are reserved documentation addresses.

`summary.json`, `commands.json`, fixture hashes, actual engine stdout/stderr,
PCAPs and logs are written only beneath the requested output directory. The
summary binds the exercised runtime source hashes. A failed run exits nonzero
and retains its partial evidence; rerun into a different fresh directory.

## Scope limits

This suite checks selected filename and PE header rules under a defined HTTP
profile: one outer response file, status 200, identity representation, one
Content-Length and one Content-Disposition field. Range responses, transfer
coding and multipart bodies stay outside that profile. The detector skips
unsupported or ambiguous metadata; that decision does not establish that the
content is benign.

Broader private evaluations are separate from this public suite. These models
do not establish PE loader validity, complete RFC conformance or behavior on
arbitrary network traffic. TLS decryption, packet loss, adversarial TCP
reassembly, arbitrary concurrency, MIME nesting and other resource limits need
separate tests.

Relevant format references: [PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[RFC 6266](https://www.rfc-editor.org/rfc/rfc6266),
[RFC 8187](https://www.rfc-editor.org/rfc/rfc8187), and
[RFC 5646](https://www.rfc-editor.org/rfc/rfc5646).
