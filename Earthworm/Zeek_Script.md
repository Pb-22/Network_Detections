# EarthWorm Zeek Detector

This Zeek script detects two observed stages of EarthWorm reverse-SOCKS activity based on packet content rather than a fixed port.

## What it detects

### 1. Setup stage control sequence

Looks for:

- client -> server: `01 01 00 00 00 00`
- server -> client: `01 02 00 00 00 00`

If that sequence is seen on the same connection, the script raises:

- `EarthWorm_Setup_Stage_Control_Sequence`

It also tracks an optional follow-on control message:

- server -> client: `01 03 00 00 00 00`

### 2. Post-setup request stage SOCKS sequence

Looks for:

- client -> server: `01 04 00 00 00 00`
- server -> client: `01 05 00 00 00 00`
- server -> client: `05 02 00 01`

If that sequence is seen on the same connection, the script raises:

- `EarthWorm_Post_Setup_Request_Stage_SOCKS_Sequence`

## Design notes

- Uses `tcp_contents` to inspect raw payload in both directions.
- Enables full content delivery with:
  - `tcp_content_deliver_all_orig = T`
  - `tcp_content_deliver_all_resp = T`
- Tracks state per connection `uid`.
- Cleans up per-connection state in `connection_state_remove`.

## Zeek script

```zeek
@load base/frameworks/notice

module EarthWorm;

export {
    redef enum Notice::Type += {
        EarthWorm_Setup_Stage_Control_Sequence,
        EarthWorm_Post_Setup_Request_Stage_SOCKS_Sequence
    };
}

redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;

global setup_stage: table[string] of count &default=0;
global setup_alerted: table[string] of bool &default=F;
global req_stage: table[string] of count &default=0;
global req_alerted: table[string] of bool &default=F;

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

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    local uid = c$uid;

    # Group 1: setup-stage control sequence
    if ( is_orig && setup_stage[uid] == 0 && is_6b_control(contents, "\x01\x01") )
        setup_stage[uid] = 1;

    if ( ! is_orig && setup_stage[uid] == 1 && is_6b_control(contents, "\x01\x02") && ! setup_alerted[uid] )
        {
        setup_stage[uid] = 2;
        NOTICE([
            $note=EarthWorm_Setup_Stage_Control_Sequence,
            $msg=fmt("EarthWorm like setup stage control sequence on %s -> %s uid=%s", c$id$orig_h, c$id$resp_h, uid),
            $conn=c,
            $identifier=cat("ew-setup|", uid)
        ]);
        setup_alerted[uid] = T;
        }

    # Optional continuation / corroboration.
    if ( ! is_orig && setup_stage[uid] >= 1 && is_6b_control(contents, "\x01\x03") )
        setup_stage[uid] = 3;

    # Group 2: post-setup request stage SOCKS sequence
    if ( is_orig && req_stage[uid] == 0 && is_6b_control(contents, "\x01\x04") )
        req_stage[uid] = 1;

    if ( ! is_orig && req_stage[uid] == 1 && is_6b_control(contents, "\x01\x05") )
        req_stage[uid] = 2;

    if ( ! is_orig && req_stage[uid] == 2 && is_4b_socks(contents) && ! req_alerted[uid] )
        {
        req_stage[uid] = 3;
        NOTICE([
            $note=EarthWorm_Post_Setup_Request_Stage_SOCKS_Sequence,
            $msg=fmt("EarthWorm like post setup request stage SOCKS sequence on %s -> %s uid=%s", c$id$orig_h, c$id$resp_h, uid),
            $conn=c,
            $identifier=cat("ew-request|", uid)
        ]);
        req_alerted[uid] = T;
        }
    }

event connection_state_remove(c: connection)
    {
    local uid = c$uid;
    delete setup_stage[uid];
    delete setup_alerted[uid];
    delete req_stage[uid];
    delete req_alerted[uid];
    }
```
