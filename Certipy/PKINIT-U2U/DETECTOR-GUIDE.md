# Detector guide

## Analytic contract

`Zeek script/pkinit-u2u.zeek` emits `PKINIT_U2U::Self_Targeted_Ticket` and one `pkinit_u2u.log` record after the following observed chain:

1. A certificate-bearing AS request and certificate-bearing AS response pair successfully, with consistent client/realm and a local-realm TGT.
2. Within five minutes of that AS response, a TGS request authenticates with the **same ticket**. The ticket identity is a SHA-256 digest of normalized realm, normalized service, encryption type and encrypted ticket content, separated by NUL bytes. The detector stores/logs the digest, not the ticket ciphertext or a session key.
3. The request has wire ENC-TKT-IN-SKEY, exactly one additional ticket, and that ticket's identity equals the authenticating TGT and the earlier AS-issued TGT.
4. The requested service is the AS client account itself, with a matching realm.
5. Within 30 seconds, a TGS response has the matching client/realm and the requested ticket service/realm. Only then is issuance reported.

Principal/realm comparisons are case-insensitive. Other KDC flags are not a fixed Certipy fingerprint. The implementation does not require source-IP equality, infer an absent request `cname`, or treat the additional ticket as interchangeable with the AP-REQ's authenticating ticket. Ticket continuity plus observable identities support the same-account sequence; the encrypted AP-REQ authenticator is not independently verified.

A TGT emits once within the retained origin/deduplication lifetime. Exact duplicate requests do not extend the pairing window. Distinct overlapping AS or TGS requests are not guessed into response pairs.

## Zeek 9.0.0 parser compatibility

### PKINIT preauthentication and certificate events

Zeek 9.0.0's native Kerberos parser consumes PA-PK-AS-REQ / PA-PK-AS-REP (16 / 17) rather than simply retaining those entries in `KDC_Request/Response$pa_data`. A test that only searches those vectors can therefore miss genuine PKINIT. The parser emits certificate-file events **before** the enclosing AS event. This script loads `base/files/x509` and observes `file_over_new_connection` with source `KRB` or `KRB_TCP`, scoped by connection UID and direction. It consumes each observation at the corresponding AS event.

A preauth-required KRB-ERROR advertising PKINIT support does **not** create certificate success. The password controls include advertised method 16 without qualifying as PKINIT. Presence of a public certificate/file is a native parser signal, not endpoint evidence or a private-key operation. The certificate-based gate is version-/parser-dependent and intentionally conservative; PKINIT forms that do not yield these certificate-file observations can be missed.

### The KDC-options bit-name mismatch

RFC 4120's ENC-TKT-IN-SKEY wire mask is `0x00000008`. In Zeek **9.0.0**, `krb-protocol.pac` maps `0x8` into the record member named `renewable_ok`, and `0x4` into `enc_tkt_in_skey`. This is an implementation naming/mapping issue, not a change to the protocol's meaning. The detector therefore defaults to:

```zeek
PKINIT_U2U::legacy_zeek9_kdc_bits = T
```

With that setting it checks `opts$renewable_ok` to recognize wire `0x8`. **Do not change it merely because the field name looks wrong.** Set it to `F` only after verifying a corrected parser's actual wire-to-event mapping. No newer Zeek release is claimed compatible here without replay and parser inspection. The constructed `wrong-wire-bit` case deliberately sets the misleading `enc_tkt_in_skey` member while clearing the actual `0x8` member and must not alert.

### Ordering and response association

The AP-REQ event inside KDC preauthentication arrives before its enclosing TGS request; this supplies the authenticating ticket. Replies do not expose a clear response nonce through the API used here. The detector tracks **all AS and TGS requests**, including ordinary/nonqualifying requests, and fingerprints their full observable request structure. A second distinct outstanding request on the same connection triggers **persistent connection quarantine**.

Quarantine is **not timed**: it lasts until `connection_state_remove`. A reply, KRB-ERROR, pending-state expiry, or a later fresh candidate does not clear it. Otherwise a leftover reply could be misattributed after the original ambiguity was forgotten. This deliberately sacrifices detection on that connection rather than asserting a false sequence. The four companion cases cover AS ordinary/PKINIT overlap in both orders and TGS overlap followed by reply/error, a fresh candidate and a leftover response. Constructed event tests do not constitute authentic wire validation of every possible pipelining sequence.

## Load and deploy

Offline, from a new log directory, with absolute paths substituted for the two input paths:

```sh
zeek -Cr /path/to/positive-pkinit-u2u.pcap \
  '/path/to/Zeek script/pkinit-u2u.zeek' LogAscii::use_json=T
```

For a live installation, load **only** `pkinit-u2u.zeek` from your normal Zeek policy. Do not load the constructed event fixture. No installed site policy or sensor service is modified by this package.

Run on a single worker, or guarantee that **all related Kerberos flows** for a ticket reach the same worker. Ordinary five-tuple load balancing is not sufficient: AS and TGS can use different connections. This script's state is worker-local and there is no distributed synchronization implementation here. Inspect real packet loss, asymmetric capture, parser versions and worker routing before judging a quiet detector.

| Setting | Default | Meaning |
|---|---|---|
| `correlation_window` | `5min` | Origin retention / maximum PKINIT-to-TGS age; deduplication retention |
| `response_window` | `30sec` | Request/response pairing and short-lived parser context |
| `max_ticket_states` | `100000` | Admission cap on retained PKINIT TGT origins; not a global memory cap |
| `legacy_zeek9_kdc_bits` | `T` | Use Zeek 9.0.0's observed wire-bit mapping |

Quarantine is separate from the timed tables. Quarantine state persists for the connection lifetime; long-lived ambiguous connections and other parser/pending tables still consume resources. This is not a complete adversarial memory-budget guarantee. Measure local traffic and tune state/worker capacity before deployment.

## Output and triage

`pkinit_u2u.log` includes event time, TGS UID/connection, PKINIT UID/source, principal, realm, service, ticket digest, PKINIT age and outcome `self_targeted_u2u_ticket_issued`. The notice's `sub` field contains only the account in `principal@realm` form. The digest is a continuity identifier, **not an NT hash**.

On a notice, correlate both UIDs, account/realm, certificate-authentication events, DC ticket events, certificate enrollment history, authorized client activity and endpoint evidence. Do not label a certificate owner malicious solely from this notice. Source addresses are context, not identity proof. The protocol chain may be produced by authorized assessment or other legitimate tooling.

## Limits and expected misses

- Missing the PKINIT precursor, either direction, a required certificate-file event, the AP-REQ, the additional ticket or the successful TGS response causes a miss. The derived partial-view positive explicitly demonstrates one such false negative.
- Activity outside the timing windows, cross-worker splitting, out-of-order visibility, errors, state admission pressure, distinct overlapping requests and connection quarantine suppress detection.
- Exactly one matching additional ticket and a self-targeted local-realm account service are required. Alternate techniques, cross-realm forms, certificate-less parser signals and non-self-targeted U2U are outside the verified scope.
- Transport/parser visibility is required; encrypted tunnels or unavailable Kerberos payloads are not solved by this script. No keys, PAC decryption, client memory inspection or endpoint extraction telemetry is performed.
- Local Windows AD captures and constructed event tests demonstrate bounded behavior, not universal false-positive/false-negative rates, tool exclusivity or production approval.

## References

- [RFC 4120, Kerberos V5](https://www.rfc-editor.org/rfc/rfc4120), especially §2.9.2 and §5.4.1.
- [Zeek v9.0.0 Kerberos protocol parser](https://github.com/zeek/zeek/blob/v9.0.0/src/analyzer/protocol/krb/krb-protocol.pac): KDC-options masks and request grammar.
- [Zeek v9.0.0 Kerberos analyzer](https://github.com/zeek/zeek/blob/v9.0.0/src/analyzer/protocol/krb/krb-analyzer.pac): event construction and additional-ticket exposure.
- [Zeek v9.0.0 preauthentication handling](https://github.com/zeek/zeek/blob/v9.0.0/src/analyzer/protocol/krb/krb-padata.pac): PKINIT handling and file emission.

The version-pinned implementation and the packaged replay evidence take precedence over assumptions based on record member names alone.
