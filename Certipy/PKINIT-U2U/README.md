# PKINIT → linked self-targeted Kerberos U2U

A passive **Zeek 9.0.0** detector with authentic lab captures, negative controls, a deliberate visibility-loss example, and an offline replay suite.

The analytic recognizes a successful PKINIT AS exchange followed by a successful, linked, self-targeted U2U ticket exchange for the same account. It is **UnPAC-compatible activity, not proof of NT-hash extraction**. PKINIT alone is legitimate; U2U alone is legitimate. The RDP/NLA control demonstrates why neither is sufficient by itself.

## Start here

- [Packet guide](PACKET-GUIDE.md): frame numbers, case intent, wire fields, capture caveats.
- [Detector guide](DETECTOR-GUIDE.md): exact matching, parser compatibility, deployment and triage.
- [`validation.json`](validation.json): measured counts bound to the detector, runner, case manifest and event fixture hashes.
- [`cases.json`](cases.json): portable inputs and exact expected counts.
- [`SHA256SUMS`](SHA256SUMS): hashes of every other package file.

This is a lab-validated candidate, not a production false-positive-rate claim. Review behavior and local prevalence before operational promotion.

## Package contents

```text
PKINIT-U2U/
  README.md
  PACKET-GUIDE.md
  DETECTOR-GUIDE.md
  cases.json
  validation.json
  SHA256SUMS
  replay.py
  tests/test_replay.py
  tests/test_notice_sub.py
  Zeek script/pkinit-u2u.zeek
  Zeek script/event-regressions.zeek
  pcap/*.pcap
```

Seven captures are authentic exchanges generated in an isolated Windows AD lab. The eighth is explicitly derived by omitting the positive's first 15 packet records. It is still a positive activity trace, with an **expected false negative** because the prerequisite PKINIT exchange is absent. It is not a benign control. The constructed Zeek event fixtures are a separate state-machine test plane, not additional authentic traffic.

Capture hostnames, accounts and addresses belong to the synthetic lab. Original approved capture bytes are retained; these are not anonymized rewrites. Captures contain protocol identities, public certificates and encrypted authentication material. Treat PCAPs as security-sensitive artifacts even though publication checks found no known lab passwords, recovered NT hashes or private-key patterns in the reviewed surfaces. Do not use these captures as live credentials or import them into production authentication tooling. No account setup, credential store, management transport, private key, ticket cache or controller transcript is included.

## Reproduce offline

Requirements: Python **3.9+** (standard library only) and a local Zeek installation. Actual engine validation used **Zeek 9.0.0**, one offline process per case. The runner does not install Zeek or contact a remote sensor. Run commands from this directory; keep generated logs outside it.

```sh
sha256sum -c SHA256SUMS
python3 -B -m unittest discover -s tests -v
python3 -B replay.py --output ../pkinit-u2u-replay
python3 -B replay.py --events --output ../pkinit-u2u-replay-with-events
```

Use a **new** output directory each time. For a non-PATH executable, pass `--zeek /path/to/zeek`. For one case:

```sh
python3 -B replay.py --case positive-pkinit-u2u --output ../pkinit-u2u-one-case
```

`--case` is repeatable. Constructed cases additionally require `--events`. `python3 -B replay.py --help` lists the options. Paths containing spaces are passed as individual subprocess arguments, not through a shell. The notice output regression uses a real Zeek executable found on PATH, or supplied through `ZEEK_BIN`; it is skipped when neither is available. Set `ZEEK_BIN=/path/to/zeek` when running the tests with a non-PATH installation.

The runner verifies every PCAP, the detector and the constructed fixture against `cases.json` **before** engine execution. Each case gets an isolated log directory. It invokes `zeek -Cr` with JSON logging; `-C` disables checksum validation for offline captures, so this is not a test of live NIC checksum handling. A case passes only with:

1. engine exit code zero;
2. empty standard output and standard error;
3. zero `reporter.log` ERROR records;
4. exactly the expected number of `pkinit_u2u.log` records;
5. exactly the same number of `PKINIT_U2U::Self_Targeted_Ticket` notices.

A missing target log is a valid zero, not automatically a failure. Malformed JSON, unavailable Zeek, timeouts, hash mismatches and engine failures do not become successful results. Exit status is 0 for all selected cases passing, 1 for measured count/error failures, and 2 for a runner/input/process exception. An exception can leave partial logs without a complete receipt; never interpret that as success.

`receipt.json` in the output directory is a count-only result. Raw local Zeek logs remain alongside it for investigation; do not publish those automatically. SHA-256 manifests provide byte integrity, not a digital signature or independent provenance guarantee.

## Capture outcomes

Counts below apply separately to detector records and selected notices.

| Capture stem | Type | Expected count | What it checks |
|---|---|---:|---|
| `positive-pkinit-u2u` | Authentic positive | 1 | PKINIT followed by linked same-account self-targeted U2U issuance |
| `negative-pkinit-no-hash` | Authentic negative | 0 | Certificate authentication without the follow-on U2U request |
| `negative-password-service` | Authentic negative | 0 | Password AS exchange followed by ordinary CIFS service ticket |
| `negative-pkinit-service` | Authentic negative | 0 | PKINIT followed by ordinary CIFS service ticket |
| `negative-password-self-u2u` | Authentic negative | 0 | Self-targeted U2U without a PKINIT precursor |
| `negative-cross-principal` | Authentic negative | 0 | Bob authenticates; U2U target/additional ticket belongs to Alice |
| `benign-rdp-nla-u2u` | Authentic benign protocol control | 0 | RDP/NLA produces a real U2U request and successful TGS reply |
| `partial-view-positive` | Derived visibility-loss positive | 0 | Expected false negative when PKINIT is not in the capture |

`--events` additionally exercises 31 constructed event/state cases. Five intentionally retain one detection; the others intentionally suppress detection. The fixture modifies/enqueues events while reading the positive capture. **Never load `event-regressions.zeek` on a production sensor.**

## What the notice means

Investigate the account's certificate authentication and subsequent ticket activity. Corroborate with authorized client/process evidence and DC authentication events. The detector establishes observed ticket continuity and identity consistency; it cannot verify the encrypted AP-REQ authenticator, decrypt the PAC, observe local key use, or show that a hash was recovered or used. A successful KDC reply is not the same as application authorization or an interactive login.

For deployment scope, parser flags and known misses, read the [detector guide](DETECTOR-GUIDE.md) before loading the script.
