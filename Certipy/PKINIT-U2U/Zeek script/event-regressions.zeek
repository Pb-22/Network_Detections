# Constructed event regressions, NOT authentic traffic or protocol outcomes.
# Loaded after the detector and driven by the real positive PCAP's native events.
module PKINIT_U2U;
export { const regression_case = "baseline" &redef; }
global injected = F;
global saved_auth: table[string] of KRB::Ticket;
global saved_candidate: table[string] of KRB::KDC_Request;
global reused_response = F;

event regression_as_certificate(c: connection)
    { add pkinit_cert[c$uid,T]; }
event regression_check_as_overlap(c: connection)
    {
    if ( c$uid !in as_pending || as_pending[c$uid]$ambiguous == F )
        Reporter::error("AS overlap was not retained as ambiguous");
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request) &priority=20
    {
    if ( regression_case == "case-normalization" ) msg$client_name=to_upper(msg$client_name);
    if ( regression_case == "missing-request-certificate" ) delete pkinit_cert[c$uid,T];
    if ( injected == F && regression_case in set("as-pkinit-then-ordinary", "as-ordinary-then-pkinit") )
        {
        injected=T;
        if ( regression_case == "as-ordinary-then-pkinit" )
            { delete pkinit_cert[c$uid,T]; event regression_as_certificate(c); }
        event krb_as_request(c,copy(msg));
        event regression_check_as_overlap(c);
        }
    }
event krb_as_response(c: connection, msg: KRB::KDC_Response) &priority=20
    {
    if ( regression_case == "missing-reply-certificate" ) delete pkinit_cert[c$uid,F];
    if ( regression_case == "wrong-as-client" ) msg$client_name="different-client";
    if ( regression_case == "wrong-as-realm" ) msg$client_realm="OTHER.EXAMPLE";
    }
event krb_ap_request(c: connection,ticket: KRB::Ticket,opts: KRB::AP_Options,in_kdc_padata: bool) &priority=20
    {
    saved_auth[c$uid]=copy(ticket);
    if ( regression_case == "wrong-auth-ticket" ) ticket$ciphertext="different-auth-ticket";
    }
event krb_tgs_request(c: connection,msg: KRB::KDC_Request) &priority=20
    {
    if ( regression_case == "case-normalization" )
        { msg$service_name=to_upper(msg$service_name);msg$service_realm=to_lower(msg$service_realm); }
    if ( regression_case == "optional-flags" )
        { msg$kdc_options$forwardable=F;msg$kdc_options$renewable=F;msg$kdc_options$disable_transited_check=F; }
    if ( regression_case == "missing-option" ) msg$kdc_options$renewable_ok=F;
    if ( regression_case == "wrong-wire-bit" )
        { msg$kdc_options$renewable_ok=F;msg$kdc_options$enc_tkt_in_skey=T; }
    if ( regression_case == "missing-additional" ) delete msg$additional_tickets;
    if ( regression_case == "extra-additional" ) msg$additional_tickets[1]=msg$additional_tickets[0];
    if ( regression_case == "wrong-additional" ) msg$additional_tickets[0]$ciphertext="different-additional-ticket";
    if ( regression_case == "wrong-target" ) msg$service_name="different-client";
    if ( regression_case == "wrong-target-realm" ) msg$service_realm="OTHER.EXAMPLE";
    if ( regression_case == "expired-pkinit" || regression_case == "out-of-order" )
        for(key in origins)
            origins[key]$issued = regression_case == "expired-pkinit" ? network_time()-301sec : network_time()+1sec;
    if ( injected == F && regression_case in set("different-nonce-pipeline","same-nonce-different-ticket-pipeline","duplicate-request") )
        {
        injected=T;
        local second=copy(msg);
        if ( regression_case == "different-nonce-pipeline" ) second$nonce=msg$nonce+1;
        if ( regression_case == "same-nonce-different-ticket-pipeline" ) second$additional_tickets[0]$ciphertext="different-pipelined-ticket";
        event krb_ap_request(c,copy(saved_auth[c$uid]),KRB::AP_Options($use_session_key=F,$mutual_required=F),T);
        event krb_tgs_request(c,second);
        }
    if ( injected == F && regression_case == "error-before-reply" )
        { injected=T;event krb_error(c,KRB::Error_Msg($error_code=7)); }
    if ( injected == F && regression_case == "ordinary-request-before-candidate" )
        {
        injected=T;
        local candidate=copy(msg);
        event krb_ap_request(c,copy(saved_auth[c$uid]),KRB::AP_Options($use_session_key=F,$mutual_required=F),T);
        event krb_tgs_request(c,candidate);
        msg$kdc_options$renewable_ok=F;
        }
    if ( injected == F && regression_case in set("overlap-reply-new-candidate-leftover", "overlap-error-new-candidate-leftover") )
        {
        injected=T;
        saved_candidate[c$uid]=copy(msg);
        local overlap=copy(msg);
        overlap$nonce=msg$nonce+1;
        event krb_ap_request(c,copy(saved_auth[c$uid]),KRB::AP_Options($use_session_key=F,$mutual_required=F),T);
        event krb_tgs_request(c,overlap);
        if ( regression_case == "overlap-error-new-candidate-leftover" )
            {
            event krb_error(c,KRB::Error_Msg($error_code=7));
            event krb_ap_request(c,copy(saved_auth[c$uid]),KRB::AP_Options($use_session_key=F,$mutual_required=F),T);
            event krb_tgs_request(c,copy(saved_candidate[c$uid]));
            }
        }
    }
event krb_tgs_response(c: connection,msg: KRB::KDC_Response) &priority=20
    {
    if ( regression_case == "wrong-response-client" ) msg$client_name="different-client";
    if ( regression_case == "wrong-response-realm" ) msg$client_realm="OTHER.EXAMPLE";
    if ( regression_case == "wrong-response-service" ) msg$ticket$service_name="different-client";
    if ( regression_case == "stale-response" && c$uid in tgs_pending ) tgs_pending[c$uid]$started=network_time()-31sec;
    if ( regression_case == "duplicate-reply" && injected == F )
        { injected=T;event krb_tgs_response(c,copy(msg)); }
    if ( regression_case == "overlap-reply-new-candidate-leftover" && reused_response == F )
        {
        reused_response=T;
        event krb_ap_request(c,copy(saved_auth[c$uid]),KRB::AP_Options($use_session_key=F,$mutual_required=F),T);
        event krb_tgs_request(c,copy(saved_candidate[c$uid]));
        event krb_tgs_response(c,copy(msg));
        }
    }
