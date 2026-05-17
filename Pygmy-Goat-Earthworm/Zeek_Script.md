# Pygmy Goat / EarthWorm Zeek Detector

This Zeek script tracks the pool-aware request-stage sequence and only alerts when the trailing 4-byte pool value in `01 05` matches what was previously seen in `01 04` on the same connection.

## What it detects

### Pool-aware request-stage SOCKS sequence

Looks for:

- client -> server: `01 04 <pool>`
- server -> client: `01 05 <pool>`
- server -> client: `05 02 00 01`

If the `01 04` and `01 05` trailing bytes match, the script raises:

- `EarthWorm_Post_Setup_Request_Stage_SOCKS_Sequence_PoolAware`

## Design notes

- Uses `tcp_contents` to inspect raw payload in both directions.
- Enables full content delivery with:
  - `tcp_content_deliver_all_orig = T`
  - `tcp_content_deliver_all_resp = T`
- Tracks request-stage pool state per connection `uid`.
- Treats `ew-test-07` as the zero-pool baseline rather than a current alerting case.

## Zeek script

```zeek
@load base/frameworks/notice

module EarthWorm;

export {
    redef enum Notice::Type += {
        EarthWorm_Post_Setup_Request_Stage_SOCKS_Sequence_PoolAware
    };
}

redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;

global req_stage: table[string] of count &default=0;
global req_alerted: table[string] of bool &default=F;
global req_pool: table[string] of string &default="";

function has_prefix_2(contents: string, prefix: string): bool
    {
    return |contents| >= 2 && sub_bytes(contents, 0, 2) == prefix;
    }

function is_6b_control(contents: string, prefix: string): bool
    {
    return |contents| == 6 && has_prefix_2(contents, prefix);
    }

function is_4b_socks(contents: string): bool
    {
    return |contents| == 4 && contents == "\x05\x02\x00\x01";
    }

function tail4(contents: string): string
    {
    if ( |contents| < 6 )
        return "";
    return sub_bytes(contents, 2, 4);
    }

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    local uid = c$uid;

    if ( is_orig && req_stage[uid] == 0 && is_6b_control(contents, "\x01\x04") )
        {
        req_stage[uid] = 1;
        req_pool[uid] = tail4(contents);
        }

    if ( ! is_orig && req_stage[uid] == 1 && is_6b_control(contents, "\x01\x05") )
        {
        if ( req_pool[uid] == tail4(contents) )
            req_stage[uid] = 2;
        }

    if ( ! is_orig && req_stage[uid] == 2 && is_4b_socks(contents) && ! req_alerted[uid] )
        {
        local pool = req_pool[uid];
        local pool_text = (|pool| == 4) ? string_to_ascii_hex(pool) : "unknown";
        NOTICE([
            $note=EarthWorm_Post_Setup_Request_Stage_SOCKS_Sequence_PoolAware,
            $msg=fmt("EarthWorm like post setup request stage SOCKS sequence on %s -> %s uid=%s pool=0x%s", c$id$orig_h, c$id$resp_h, uid, pool_text),
            $sub=fmt("pool=0x%s", pool_text),
            $conn=c,
            $identifier=cat("ew-request-pool|", uid)
        ]);
        req_alerted[uid] = T;
        req_stage[uid] = 3;
        }
    }

event connection_state_remove(c: connection)
    {
    local uid = c$uid;
    delete req_stage[uid];
    delete req_alerted[uid];
    delete req_pool[uid];
    }
```
