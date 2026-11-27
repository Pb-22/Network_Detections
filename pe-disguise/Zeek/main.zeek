@load base/protocols/http
@load base/frameworks/notice
@load ./pe

module PEFileDisguise;
export {
    redef enum Notice::Type += { DocumentImageMismatch };
    type Health: record {
        active_contexts: count &default=0;
        peak_active_contexts: count &default=0;
        retained_prefix_bytes: count &default=0;
        peak_retained_prefix_bytes: count &default=0;
        eligible_files: count &default=0;
        admission_drops: count &default=0;
        notices: count &default=0;
    };
    global health: Health = Health();
}
type Context: record {
    uid: string;
    id: conn_id;
    fuid: string;
    depth: count;
    filename: string;
    declared: count;
    prefix: string &default="";
    parsed: bool &default=F;
    format: string &default="";
    bad: bool &default=F;
    http_done: bool &default=F;
    file_done: bool &default=F;
    released: bool &default=F;
    seen: count &default=0;
    total: count &default=0;
};
type Headers: record {
    bad: bool &default=F;
    cd_count: count &default=0;
    cl_count: count &default=0;
    ce_count: count &default=0;
    ct_count: count &default=0;
    filename: string &default="";
    declared: count &default=0;
    files: count &default=0;
};
redef record HTTP::Info += {
    pfd_headers: Headers &default=Headers();
    pfd_context: Context &optional;
};
redef record fa_file += { pfd_context: Context &optional; };
global prefix_data: event(f: fa_file, data: string);

# Remove only this policy's exact callback instance. Other DATA_EVENT args,
# including chunk and stream companions, remain attached to the native file.
function stop_prefix(f: fa_file)
    { Files::remove_analyzer(f,Files::ANALYZER_DATA_EVENT,[$stream_event=prefix_data]); }

function release_prefix(x: Context)
    {
    health$retained_prefix_bytes-=|x$prefix|;
    x$prefix="";
    }
# Release both owned budgets once. Tombstone the shared context so late native
# callbacks cannot reacquire prefix bytes, emit a Notice or decrement again.
function release_context(x: Context)
    {
    if ( x$released ) return;
    release_prefix(x); x$released=T; --health$active_contexts;
    }
function reject_context(x: Context)
    { x$bad=T; release_context(x); }
function finish(x: Context)
    {
    if ( x$released ) return;
    if ( x$bad ) { reject_context(x); return; }
    if ( ! x$http_done || ! x$file_done ) return;
    if ( completion_ok(x$http_done,x$file_done,x$bad,x$seen,x$total,x$declared) && x$format!="" )
        {
        NOTICE([$note=DocumentImageMismatch,
            $msg="PE content advertised with a document or image filename",
            $sub=fmt("fuid=%s;uid=%s;filename_hex=%s;filename_source=content-disposition;format=%s;observed_bytes=%d;declared_bytes=%d;orig_p=%s;resp_p=%s",
                x$fuid,x$uid,bytestring_to_hexstr(x$filename),x$format=="pe32" ? "PE32" : "PE32+",x$seen,x$declared,x$id$orig_p,x$id$resp_p),
            $uid=x$uid,$id=x$id,$fuid=x$fuid,$src=x$id$orig_h,$dst=x$id$resp_h,$p=x$id$resp_p]);
        ++health$notices;
        }
    release_context(x);
    }
function decimal_length(value: string): count
    {
    local v=strip(value);
    if ( |v|>max_header_value_bytes || ! ( /^[0-9]+$/ == v ) ) return 0;
    local n: count=0; local i: count=0;
    while ( i<|v| )
        {
        local digit=octet(v,i)-48; ++i;
        if ( n>(max_object_bytes-digit)/10 ) return 0;
        n=n*10+digit;
        }
    return n;
    }
event http_reply(c: connection, version: string, code: count, reason: string) &priority=0
    { c$http$pfd_headers=Headers(); }
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=0
    {
    if ( is_orig || ! c?$http ) return;
    local h=c$http$pfd_headers;
    if ( c$http$resp_mime_depth!=1 ) { h$bad=T; return; }
    if ( |value|>max_header_value_bytes ) { h$bad=T; return; }
    if ( name=="CONTENT-DISPOSITION" )
        { ++h$cd_count; h$filename=selected_filename(value); }
    else if ( name=="CONTENT-LENGTH" )
        {
        ++h$cl_count; h$declared=decimal_length(value);
        if ( h$declared==0 ) h$bad=T;
        }
    else if ( name=="TRANSFER-ENCODING" || name=="CONTENT-RANGE" ) h$bad=T;
    else if ( name=="CONTENT-ENCODING" )
        { ++h$ce_count; if ( to_lower(strip(value))!="identity" || h$ce_count>1 ) h$bad=T; }
    else if ( name=="CONTENT-TYPE" )
        { ++h$ct_count; if ( /^[ \t]*multipart\// in to_lower(value) || h$ct_count>1 ) h$bad=T; }
    if ( h$cd_count>1 || h$cl_count>1 ) h$bad=T;
    }
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=0
    {
    if ( f$source!="HTTP" || ! f?$http || is_orig || ! f?$is_orig || f$is_orig || f?$parent_id ) return;
    local h=f$http$pfd_headers; ++h$files;
    if ( f$http?$pfd_context ) { reject_context(f$http$pfd_context); return; }
    if ( h$bad || h$files!=1 || h$cd_count!=1 || h$cl_count!=1 || h$filename=="" ||
         ! f$http?$status_code || f$http$status_code!=200 || f$http$range_request ||
         f$http$resp_mime_depth!=1 || ! f$http?$resp_fuids || |f$http$resp_fuids|!=1 || f$http$resp_fuids[0]!=f$id ) return;
    if ( ! ( /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|ods|odp|jpg|jpeg|png|gif|bmp|tif|tiff|webp|svg)$/ in to_lower(h$filename) ) ) return;
    if ( health$active_contexts>=max_active_contexts ) { ++health$admission_drops; return; }
    local x=Context($uid=c$uid,$id=c$id,$fuid=f$id,$depth=f$http$trans_depth,$filename=h$filename,$declared=h$declared);
    f$pfd_context=x; f$http$pfd_context=x;
    ++health$active_contexts; ++health$eligible_files;
    if ( health$active_contexts>health$peak_active_contexts ) health$peak_active_contexts=health$active_contexts;
    if ( ! Files::add_analyzer(f,Files::ANALYZER_DATA_EVENT,[$stream_event=prefix_data]) ) reject_context(x);
    }
event prefix_data(f: fa_file, data: string)
    {
    if ( ! f?$pfd_context ) return;
    local x=f$pfd_context;
    if ( x$released || x$parsed || x$bad ) { stop_prefix(f); return; }
    local cursor: count=0;
    while ( T )
        {
        local need=needed(x$prefix);
        if ( need>max_prefix_bytes || need>x$declared )
            { reject_context(x); stop_prefix(f); return; }
        if ( |x$prefix|>=need )
            {
            x$format=pe_format(x$prefix,x$declared); x$parsed=T;
            if ( x$format=="" ) reject_context(x); else release_prefix(x);
            stop_prefix(f); return;
            }
        if ( cursor==|data| ) return;
        local remaining=need-|x$prefix|;
        local available=|data|-cursor;
        local take=available<remaining ? available : remaining;
        x$prefix=cat(x$prefix,part(data,cursor,take)); cursor+=take;
        health$retained_prefix_bytes+=take;
        if ( health$retained_prefix_bytes>health$peak_retained_prefix_bytes ) health$peak_retained_prefix_bytes=health$retained_prefix_bytes;
        }
    }
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=0
    {
    if ( is_orig || ! c?$http || ! c$http?$pfd_context ) return;
    local x=c$http$pfd_context;
    x$http_done=T;
    if ( stat$interrupted || stat$content_gap_length!=0 || stat$body_length!=x$declared ||
         c$http$trans_depth!=x$depth || c$uid!=x$uid || c$http$pfd_headers$files!=1 || c$http$pfd_headers$bad ) x$bad=T;
    finish(x);
    }
event file_state_remove(f: fa_file) &priority=0
    {
    if ( ! f?$pfd_context ) return;
    local x=f$pfd_context;
    x$file_done=T; x$seen=f$seen_bytes;
    if ( f?$total_bytes ) x$total=f$total_bytes; else x$bad=T;
    if ( f$missing_bytes!=0 || f$overflow_bytes!=0 || f$info$timedout || ! x$parsed ) x$bad=T;
    finish(x);
    }
event file_gap(f: fa_file, offset: count, len: count)
    { if ( f?$pfd_context ) reject_context(f$pfd_context); }
event file_reassembly_overflow(f: fa_file, offset: count, skipped: count)
    { if ( f?$pfd_context ) reject_context(f$pfd_context); }
event file_timeout(f: fa_file) &priority=0
    { if ( f?$pfd_context ) reject_context(f$pfd_context); }
