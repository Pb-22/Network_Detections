## Passive Windows AD PKINIT followed by linked self-targeted U2U issuance.
## Zeek 9.0.0. No keys, decryption, endpoint logs, or asset inventory required.
## Run on one worker, or ensure all related Kerberos flows reach the same worker.
@load base/protocols/krb
@load base/frameworks/notice
@load base/files/x509

module PKINIT_U2U;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { Self_Targeted_Ticket };

    ## Starts at the successful AS response, not the first preauth attempt.
    const correlation_window = 5min &redef;
    const response_window = 30sec &redef;
    const max_ticket_states: count = 100000 &redef;
    ## Zeek 9.0.0 krb-protocol.pac maps wire 0x8 to renewable_ok and
    ## 0x4 to enc_tkt_in_skey. RFC 4120 assigns ENC-TKT-IN-SKEY to 0x8.
    ## Set F only for a parser whose corrected mapping has been verified.
    const legacy_zeek9_kdc_bits = T &redef;

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        pkinit_uid: string &log;
        pkinit_client: addr &log;
        principal: string &log;
        realm: string &log;
        service: string &log;
        tgt_sha256: string &log;
        pkinit_age: interval &log;
        outcome: string &log;
    };
    global log_pkinit_u2u: event(rec: Info);
}

type AS_Pending: record {
    signature: string;
    qualified: bool &default=F;
    client: string;
    realm: string;
    started: time;
    nonce: count;
    ambiguous: bool &default=F;
};
type Origin: record {
    client: string;
    realm: string;
    issued: time;
    uid: string;
    source: addr;
};
type TGS_Pending: record {
    signature: string;
    qualified: bool &default=F;
    tgt: string;
    service: string;
    realm: string;
    started: time;
    nonce: count;
    ambiguous: bool &default=F;
};

global as_pending: table[string] of AS_Pending &create_expire=response_window;
global origins: table[string] of Origin &create_expire=correlation_window;
global auth_ticket: table[string] of string &create_expire=response_window;
global tgs_pending: table[string] of TGS_Pending &create_expire=response_window;
global emitted: set[string] &create_expire=correlation_window;
global pkinit_cert: set[string, bool] &create_expire=response_window;
# Overlap destroys reply association. A reply, error, or timer cannot prove the
# connection is drained, so quarantine lasts until connection removal.
global quarantined: set[string];

# Zeek 9 consumes PA-PK-AS-REQ/REP (16/17) instead of copying them to
# KDC_Request/Response$pa_data. Its native parser emits their certificate
# files before the enclosing AS event. Error-advertised methods create no file.
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
    {
    if ( f$source == "KRB" || f$source == "KRB_TCP" )
        add pkinit_cert[c$uid, is_orig];
    }

function ticket_id(ticket: KRB::Ticket): string
    {
    if ( ! ticket?$ciphertext || ticket$ciphertext == "" )
        return "";
    # Store a digest, never ciphertext or a credential/session key.
    return sha256_hash(cat(to_lower(ticket$realm), "\x00",
                           to_lower(ticket$service_name), "\x00",
                           fmt("%d", ticket$cipher), "\x00", ticket$ciphertext));
    }

function local_tgt(ticket: KRB::Ticket, realm: string): bool
    {
    return to_lower(ticket$realm) == to_lower(realm) &&
           to_lower(ticket$service_name) == to_lower(cat("krbtgt/", realm));
    }

function wire_u2u(opts: KRB::KDC_Options): bool
    {
    return legacy_zeek9_kdc_bits ? opts$renewable_ok : opts$enc_tkt_in_skey;
    }

event zeek_init() &priority=5
    {
    Log::create_stream(LOG, [$columns=Info, $ev=log_pkinit_u2u, $path="pkinit_u2u"]);
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    local certificate_seen = [c$uid, T] in pkinit_cert;
    delete pkinit_cert[c$uid, T];
    if ( c$uid in quarantined )
        return;
    local signature = sha256_hash(fmt("%s/%s", certificate_seen, msg));
    if ( c$uid in as_pending )
        {
        if ( as_pending[c$uid]$signature != signature )
            {
            as_pending[c$uid]$ambiguous = T;
            add quarantined[c$uid];
            }
        return;
        }
    # Track non-PKINIT requests as well as qualified precursors.
    local a = AS_Pending($signature=signature,
        $client=msg?$client_name ? msg$client_name : "",
        $realm=msg?$service_realm ? msg$service_realm : "",
        $started=network_time(), $nonce=msg?$nonce ? msg$nonce : 0,
        $qualified=certificate_seen && msg?$client_name && msg?$service_realm && msg?$nonce);
    as_pending[c$uid] = a;
    }

event krb_as_response(c: connection, msg: KRB::KDC_Response)
    {
    local certificate_seen = [c$uid, F] in pkinit_cert;
    delete pkinit_cert[c$uid, F];
    if ( c$uid in quarantined || c$uid !in as_pending )
        return;
    local a = as_pending[c$uid];
    delete as_pending[c$uid];
    if ( a$qualified == F || a$ambiguous || network_time()-a$started > response_window ||
         certificate_seen == F || ! msg?$client_realm ||
         to_lower(a$client) != to_lower(msg$client_name) ||
         to_lower(a$realm) != to_lower(msg$client_realm) ||
         ! local_tgt(msg$ticket, msg$client_realm) )
        return;
    local key = ticket_id(msg$ticket);
    if ( key == "" || |origins| >= max_ticket_states )
        return;
    # Do not refresh the window on duplicate AS responses.
    if ( key !in origins )
        origins[key] = Origin($client=msg$client_name, $realm=msg$client_realm,
                              $issued=network_time(), $uid=c$uid, $source=c$id$orig_h);
    }

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options, in_kdc_padata: bool)
    {
    if ( in_kdc_padata == F )
        return;
    local key = ticket_id(ticket);
    # The parser emits this before the enclosing TGS request. This is the
    # authenticating TGT, not the independently supplied additional ticket.
    if ( c$uid in auth_ticket && auth_ticket[c$uid] != key )
        auth_ticket[c$uid] = "";
    else
        auth_ticket[c$uid] = key;
    }

event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
    {
    local key = c$uid in auth_ticket ? auth_ticket[c$uid] : "";
    delete auth_ticket[c$uid];
    if ( c$uid in quarantined )
        return;
    local signature = sha256_hash(cat(key, fmt("%s", msg)));
    # Any second distinct outstanding request makes passive response pairing
    # ambiguous, including an ordinary request interleaved with a candidate.
    if ( c$uid in tgs_pending )
        {
        if ( tgs_pending[c$uid]$signature != signature )
            {
            tgs_pending[c$uid]$ambiguous = T;
            add quarantined[c$uid];
            }
        return;
        }
    # Track ordinary requests too. Otherwise an earlier ordinary reply could be
    # mistaken for a later candidate on a pipelined connection.
    tgs_pending[c$uid] = TGS_Pending($signature=signature, $tgt=key,
        $service=msg?$service_name ? msg$service_name : "",
        $realm=msg?$service_realm ? msg$service_realm : "",
        $started=network_time(), $nonce=msg?$nonce ? msg$nonce : 0);
    if ( key == "" || key !in origins ||
         ! msg?$kdc_options || ! wire_u2u(msg$kdc_options) ||
         ! msg?$additional_tickets || |msg$additional_tickets| != 1 ||
         ! msg?$service_name || ! msg?$service_realm || ! msg?$nonce ||
         ticket_id(msg$additional_tickets[0]) != key )
        return;
    local o = origins[key];
    if ( network_time() < o$issued || network_time()-o$issued > correlation_window ||
         to_lower(msg$service_realm) != to_lower(o$realm) ||
         to_lower(msg$service_name) != to_lower(o$client) )
        return;
    tgs_pending[c$uid]$qualified = T;
    }

event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( c$uid in quarantined || c$uid !in tgs_pending )
        return;
    local t = tgs_pending[c$uid];
    delete tgs_pending[c$uid];
    if ( t$qualified == F || t$ambiguous || t$tgt !in origins || t$tgt in emitted ||
         network_time() < t$started || network_time()-t$started > response_window ||
         ! msg?$client_realm )
        return;
    local o = origins[t$tgt];
    if ( network_time()-o$issued > correlation_window ||
         to_lower(msg$client_name) != to_lower(o$client) ||
         to_lower(msg$client_realm) != to_lower(o$realm) ||
         to_lower(msg$ticket$realm) != to_lower(t$realm) ||
         to_lower(msg$ticket$service_name) != to_lower(t$service) )
        return;
    add emitted[t$tgt];
    Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $id=c$id,
        $pkinit_uid=o$uid, $pkinit_client=o$source, $principal=msg$client_name,
        $realm=msg$client_realm, $service=msg$ticket$service_name,
        $tgt_sha256=t$tgt, $pkinit_age=network_time()-o$issued,
        $outcome="self_targeted_u2u_ticket_issued"));
    NOTICE([$note=Self_Targeted_Ticket, $conn=c, $identifier=t$tgt,
        $suppress_for=correlation_window,
        $msg=fmt("PKINIT followed by linked self-targeted U2U ticket issuance for %s@%s",
                 msg$client_name, msg$client_realm),
        $sub=fmt("%s@%s", msg$client_name, msg$client_realm)]);
    }

event krb_error(c: connection, msg: KRB::Error_Msg)
    {
    # Advertised preauth methods in KRB-ERROR never establish PKINIT success.
    delete as_pending[c$uid];
    delete auth_ticket[c$uid];
    delete tgs_pending[c$uid];
    delete pkinit_cert[c$uid, T];
    delete pkinit_cert[c$uid, F];
    }

event connection_state_remove(c: connection)
    {
    delete quarantined[c$uid];
    delete as_pending[c$uid];
    delete auth_ticket[c$uid];
    delete tgs_pending[c$uid];
    delete pkinit_cert[c$uid, T];
    delete pkinit_cert[c$uid, F];
    }
