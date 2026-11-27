@load ./filename
module PEFileDisguise;
export {
    global pe_format: function(prefix: string, declared: count): string;
    global completion_ok: function(http_done: bool, file_done: bool, bad: bool, seen: count, total: count, declared: count): bool;
}
function le(s: string, offset: count, width: count): count
    { return bytestring_to_count(part(s,offset,width),T); }
# Return required header bytes; a value beyond the cap is an abstention.
function needed(s: string): count
    {
    if ( |s|<64 ) return 64;
    if ( part(s,0,2)!="MZ" ) return max_prefix_bytes+1;
    local nt=le(s,60,4);
    if ( nt<64 || nt+24>max_prefix_bytes ) return max_prefix_bytes+1;
    if ( |s|<nt+24 ) return nt+24;
    return nt+24+le(s,nt+20,2)+40*le(s,nt+6,2);
    }
function pe_format(prefix: string, declared: count): string
    {
    if ( declared>max_object_bytes || |prefix|<64 || part(prefix,0,2)!="MZ" ) return "";
    local nt=le(prefix,60,4);
    if ( nt<64 || nt+24>|prefix| || part(prefix,nt,4)!="PE\x00\x00" ) return "";
    local machine=le(prefix,nt+4,2);
    local sections=le(prefix,nt+6,2);
    local optsize=le(prefix,nt+20,2);
    local opt=nt+24; local table_end=opt+optsize+40*sections;
    if ( sections==0 || sections>max_sections || table_end>max_prefix_bytes || table_end>|prefix| || table_end>declared ) return "";
    local magic=le(prefix,opt,2); local fixed: count; local format: string;
    if ( machine==0x14c && magic==0x10b ) { fixed=96; format="pe32"; }
    else if ( (machine==0x8664 || machine==0xaa64) && magic==0x20b ) { fixed=112; format="pe32plus"; }
    else return "";
    # PE/COFF permits optional-header padding. Both declared bounds must
    # contain every advertised directory; neither requires exact equality.
    if ( optsize<fixed || fixed+8*le(prefix,opt+fixed-4,4)>optsize || le(prefix,opt+fixed-4,4)>16 ) return "";
    local headers=le(prefix,opt+60,4);
    local alignment=le(prefix,opt+36,4);
    if ( headers<table_end || headers>declared || alignment==0 || headers%alignment!=0 ) return "";
    local ends: vector of count=vector(); local starts: vector of count=vector();
    local i: count=0;
    while ( i<sections )
        {
        local sec=opt+optsize+40*i;
        local size=le(prefix,sec+16,4); local start=le(prefix,sec+20,4);
        if ( size>0 )
            {
            if ( start<headers || start>declared || size>declared-start || start%alignment!=0 ) return "";
            for ( j in ends ) if ( start<ends[j] && start+size>starts[j] ) return "";
            starts+=start; ends+=start+size;
            }
        ++i;
        }
    # Certificate directory uses a file offset, not an RVA; overlays are legal.
    if ( le(prefix,opt+fixed-4,4)>4 )
        {
        local cert=le(prefix,opt+fixed+32,4); local csize=le(prefix,opt+fixed+36,4);
        if ( (cert==0)!=(csize==0) || cert>declared || csize>declared-cert ) return "";
        }
    return format;
    }
function completion_ok(http_done: bool, file_done: bool, bad: bool, seen: count, total: count, declared: count): bool
    { return http_done && file_done && ! bad && seen==declared && total==declared; }
