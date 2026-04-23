@load base/protocols/http
@load base/protocols/ssl

module CLOUDFLARE_STAGE;

export {
    redef enum Notice::Type += {
        Suspicious_Download_After_Cloudflare_Domain
    };

    const sequence_window: interval = 5mins &redef;
    const notice_suppress: interval = 5mins &redef;
}

type CFState: record {
    ts: time;
    host: string;
    dest_ip: addr;
    uid: string;
    via: string;
};

global cf_state: table[addr] of CFState &write_expire=10mins;

redef record connection += {
    cf_req_uri: string &optional;
    cf_req_method: string &optional;
};

function norm_host(h: string): string
    {
    local x = to_lower(h);

    if ( /[.]$/ in x )
        x = sub(x, /[.]$/, "");

    return x;
    }

function is_suspicious_cloudflare_host(h: string): bool
    {
    local x = norm_host(h);

    if ( x == "trycloudflare.com" ) return T;
    if ( x == "workers.dev" ) return T;
    if ( x == "pages.dev" ) return T;
    if ( x == "r2.dev" ) return T;

    if ( /(^|[.])trycloudflare[.]com$/ in x ) return T;
    if ( /(^|[.])workers[.]dev$/ in x ) return T;
    if ( /(^|[.])pages[.]dev$/ in x ) return T;
    if ( /(^|[.])r2[.]dev$/ in x ) return T;

    return F;
    }

function is_suspicious_extension(path: string): bool
    {
    local p = to_lower(path);

    if ( /[.]wsf([?].*)?$/ in p ) return T;
    if ( /[.]bat([?].*)?$/ in p ) return T;
    if ( /[.]cmd([?].*)?$/ in p ) return T;
    if ( /[.]ps1([?].*)?$/ in p ) return T;
    if ( /[.]py([?].*)?$/ in p ) return T;
    if ( /[.]js([?].*)?$/ in p ) return T;
    if ( /[.]vbs([?].*)?$/ in p ) return T;
    if ( /[.]url([?].*)?$/ in p ) return T;

    return F;
    }

function is_suspicious_mime(ct: string): bool
    {
    local x = to_lower(ct);

    if ( /application\/octet-stream/ in x ) return T;
    if ( /text\/plain/ in x ) return T;
    if ( /application\/x-msdownload/ in x ) return T;
    if ( /application\/x-bat/ in x ) return T;
    if ( /application\/x-batch/ in x ) return T;
    if ( /application\/x-python/ in x ) return T;
    if ( /text\/x-python/ in x ) return T;
    if ( /application\/javascript/ in x ) return T;
    if ( /text\/javascript/ in x ) return T;
    if ( /application\/x-javascript/ in x ) return T;
    if ( /text\/vbscript/ in x ) return T;

    return F;
    }

function sequence_is_live(orig: addr): bool
    {
    if ( orig !in cf_state )
        return F;

    if ( network_time() - cf_state[orig]$ts > sequence_window )
        return F;

    return T;
    }

function seed_sequence(orig: addr, dest: addr, uid: string, host: string, via: string)
    {
    cf_state[orig] = [$ts=network_time(), $host=host, $dest_ip=dest, $uid=uid, $via=via];
    }

event ssl_established(c: connection)
    {
    if ( c?$ssl == F )
        return;

    if ( c$ssl?$server_name == F )
        return;

    local host = norm_host(c$ssl$server_name);

    if ( is_suspicious_cloudflare_host(host) )
        seed_sequence(c$id$orig_h, c$id$resp_h, c$uid, host, "ssl");
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( c?$http == F )
        return;

    c$cf_req_uri = original_URI;
    c$cf_req_method = method;

    if ( c$http?$host == F )
        return;

    local host = norm_host(c$http$host);

    if ( is_suspicious_cloudflare_host(host) )
        seed_sequence(c$id$orig_h, c$id$resp_h, c$uid, host, "http");
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    local orig: addr;
    local header_name: string;
    local header_val: string;
    local uri = "";
    local ext_hit = F;
    local mime_hit = F;
    local disp_hit = F;
    local matched_on = "";
    local method = "";
    local seed: CFState;

    if ( is_orig )
        return;

    if ( c?$http == F )
        return;

    orig = c$id$orig_h;

    if ( ! sequence_is_live(orig) )
        return;

    header_name = to_lower(name);
    header_val = to_lower(value);

    if ( c?$cf_req_uri )
        uri = c$cf_req_uri;

    if ( uri != "" && is_suspicious_extension(uri) )
        {
        ext_hit = T;
        matched_on = fmt("uri=%s", uri);
        }

    if ( header_name == "content-type" && is_suspicious_mime(header_val) )
        {
        mime_hit = T;
        if ( matched_on == "" )
            matched_on = fmt("content-type=%s", value);
        }

    if ( header_name == "content-disposition" )
        {
        if ( /filename\s*=\s*\"?[^\";]+[.](wsf|bat|cmd|ps1|py|js|vbs|url)\"?/ in header_val )
            {
            disp_hit = T;
            if ( matched_on == "" )
                matched_on = fmt("content-disposition=%s", value);
            }
        }

    if ( ! ext_hit && ! mime_hit && ! disp_hit )
        return;

    if ( c?$cf_req_method )
        method = to_upper(c$cf_req_method);

    seed = cf_state[orig];

    NOTICE([
        $note=Suspicious_Download_After_Cloudflare_Domain,
        $msg="Suspicious download observed after access to Cloudflare developer/tunnel domain",
        $sub=fmt("client=%s seed_host=%s seed_via=%s followon_dest=%s method=%s match=%s",
                 orig, seed$host, seed$via, c$id$resp_h, method, matched_on),
        $src=orig,
        $dst=c$id$resp_h,
        $p=c$id$resp_p,
        $conn=c,
        $identifier=fmt("%s|%s|%s", orig, seed$host, matched_on),
        $suppress_for=notice_suppress
    ]);
    }