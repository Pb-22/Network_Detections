module PEFileDisguise;
export {
    const max_prefix_bytes: count = 65536;
    const max_active_contexts: count = 128;
    const max_header_value_bytes: count = 4096;
    const max_filename_bytes: count = 255;
    const max_parameters: count = 16;
    const max_sections: count = 96;
    const max_object_bytes: count = 268435456;
    global selected_filename: function(value: string): string;
}
# All offsets below are zero based; Zeek sub_bytes uses one based offsets.
function octet(s: string, i: count): count
    { return bytestring_to_count(sub_bytes(s, i+1, 1)); }
function part(s: string, i: count, n: count): string
    { return sub_bytes(s, i+1, n); }
function token(c: string): bool
    { return /^[!#$%&'*+.^_`|~0-9A-Za-z-]$/ == c; }
function utf8_ok(s: string): bool
    {
    local i: count = 0;
    while ( i < |s| )
        {
        local b=octet(s,i); ++i;
        if ( b < 128 ) next;
        local n: count; local lo: count=128; local hi: count=191;
        if ( b >= 194 && b <= 223 ) n=1;
        else if ( b >= 224 && b <= 239 )
            { n=2; if ( b==224 ) lo=160; if ( b==237 ) hi=159; }
        else if ( b >= 240 && b <= 244 )
            { n=3; if ( b==240 ) lo=144; if ( b==244 ) hi=143; }
        else return F;
        if ( i+n > |s| || octet(s,i)<lo || octet(s,i)>hi ) return F;
        ++i;
        while ( n>1 )
            { if ( octet(s,i)<128 || octet(s,i)>191 ) return F; ++i; --n; }
        }
    return T;
    }
function meaningful(s: string): bool
    {
    if ( |s|==0 || |s|>max_filename_bytes || /^[ .]|[ .]$/ in s ) return F;
    local i: count=0;
    while ( i<|s| )
        {
        local b=octet(s,i); ++i;
        if ( b<32 || b==127 || b==47 || b==92 || b==58 ) return F;
        }
    return T;
    }
# RFC5646 sections 2.1, 2.2.5 and 2.2.6: well-formed syntax only.
# No registry/locale semantics. RFC8187 permits the language to be absent.
function language_ok(language: string): bool
    {
    if ( language=="" ) return T;
    if ( |language|>max_header_value_bytes ) return F;
    local tag=to_lower(language);
    local grandfathered: set[string]={
        "en-gb-oed", "i-ami", "i-bnn", "i-default", "i-enochian",
        "i-hak", "i-klingon", "i-lux", "i-mingo", "i-navajo", "i-pwn",
        "i-tao", "i-tay", "i-tsu", "sgn-be-fr", "sgn-be-nl", "sgn-ch-de",
        "art-lojban", "cel-gaulish", "no-bok", "no-nyn", "zh-guoyu",
        "zh-hakka", "zh-min", "zh-min-nan", "zh-xiang"
    };
    if ( tag in grandfathered ) return T;
    if ( /^x(-[a-z0-9]{1,8})+$/ == tag ) return T;
    if ( ! ( /^([a-z]{2,3}(-[a-z]{3}){0,3}|[a-z]{4}|[a-z]{5,8})(-[a-z]{4})?(-([a-z]{2}|[0-9]{3}))?(-([a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*(-[0-9a-wy-z](-[a-z0-9]{2,8})+)*(-x(-[a-z0-9]{1,8})+)?$/ == tag ) ) return F;
    local subtags=split_string(tag,/-/);
    local i: count=1;
    if ( |subtags[0]|<=3 )
        while ( i<|subtags| && i<=3 && /^[a-z]{3}$/ == subtags[i] ) ++i;
    if ( i<|subtags| && /^[a-z]{4}$/ == subtags[i] ) ++i;
    if ( i<|subtags| && /^([a-z]{2}|[0-9]{3})$/ == subtags[i] ) ++i;
    local variants: set[string]=set();
    while ( i<|subtags| && /^([a-z0-9]{5,8}|[0-9][a-z0-9]{3})$/ == subtags[i] )
        {
        if ( subtags[i] in variants ) return F;
        add variants[subtags[i]]; ++i;
        }
    local singletons: set[string]=set();
    while ( i<|subtags| )
        {
        if ( subtags[i]=="x" ) return T;
        if ( subtags[i] in singletons ) return F;
        add singletons[subtags[i]]; ++i;
        while ( i<|subtags| && |subtags[i]|>1 ) ++i;
        }
    return T;
    }
function selected_filename(value: string): string
    {
    if ( |value|==0 || |value|>max_header_value_bytes ) return "";
    local i: count=0; local start: count;
    while ( i<|value| && /[ \t]/ == part(value,i,1) ) ++i;
    start=i;
    while ( i<|value| && token(part(value,i,1)) ) ++i;
    local disposition=to_lower(part(value,start,i-start));
    if ( disposition!="attachment" && disposition!="inline" ) return "";
    local params: set[string]=set(); local plain=""; local extended="";
    while ( i<|value| )
        {
        while ( i<|value| && /[ \t]/ == part(value,i,1) ) ++i;
        if ( i==|value| ) break;
        if ( part(value,i,1)!=";" ) return "";
        ++i;
        while ( i<|value| && /[ \t]/ == part(value,i,1) ) ++i;
        start=i;
        while ( i<|value| && token(part(value,i,1)) ) ++i;
        if ( i==start ) return "";
        local key=to_lower(part(value,start,i-start));
        if ( /^filename\*/ in key && key!="filename*" ) return "";
        if ( key in params || |params|>=max_parameters ) return "";
        add params[key];
        while ( i<|value| && /[ \t]/ == part(value,i,1) ) ++i;
        if ( i==|value| || part(value,i,1)!="=" ) return "";
        ++i;
        while ( i<|value| && /[ \t]/ == part(value,i,1) ) ++i;
        local v=""; local quoted=F;
        if ( i<|value| && part(value,i,1)=="\"" )
            {
            quoted=T; ++i; local closed=F;
            while ( i<|value| )
                {
                local c=part(value,i,1); ++i;
                if ( c=="\"" ) { closed=T; break; }
                if ( c=="\\" )
                    { if ( i==|value| ) return ""; c=part(value,i,1); ++i; }
                if ( /[\x00-\x08\x0a-\x1f\x7f]/ in c ) return "";
                v=cat(v,c);
                }
            if ( ! closed ) return "";
            }
        else
            {
            start=i;
            while ( i<|value| && token(part(value,i,1)) ) ++i;
            if ( i==start ) return "";
            v=part(value,start,i-start);
            }
        if ( key=="filename" ) plain=v;
        else if ( key=="filename*" )
            {
            if ( quoted || ! ( /^[uU][tT][fF]-8'[A-Za-z0-9-]*'/ in v ) ) return "";
            local language=sub(sub(v,/^[^']*'/,""),/'.*$/,"");
            if ( ! language_ok(language) ) return "";
            local encoded=sub(v,/^[^']*'[^']*'/,"");
            # Reject malformed escapes and bytes outside RFC8187 attr-char.
            if ( ! ( /^([A-Za-z0-9!#$&+.^_`|~-]|%[A-Fa-f0-9]{2})*$/ == encoded ) ) return "";
            extended=unescape_URI(encoded);
            if ( ! utf8_ok(extended) || ! meaningful(extended) ) return "";
            }
        }
    if ( "filename*" in params ) return extended;
    if ( "filename" in params && ! meaningful(plain) ) return "";
    # First-profile encoding scope: unsupported unlabelled legacy bytes abstain.
    # Apply after extended selection so a valid UTF-8 filename* still wins.
    if ( ! utf8_ok(plain) ) return "";
    return plain;
    }

