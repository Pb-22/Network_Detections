# Pygmy Goat / EarthWorm Suricata Rules

These notes extend the existing Earthworm detection work with the pool-number behavior documented in the UK National Cyber Security Centre (NCSC) *Pygmy Goat* malware analysis.

## Reference

- UK National Cyber Security Centre (NCSC), *Malware Analysis Report: Pygmy Goat*
- URL: <https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat.pdf>
- Relevant pages:
  - **Page 20**: `01 03` assign pool number, `01 04` tunnel request, `01 05` tunnel response

## What matters here

The key follow-on question was not just whether `01 04` and `01 05` appear, but whether the trailing 4-byte pool value is reused correctly.

The validated Suricata path is now the Lua-backed request-stage sequence:

- client -> server: `01 04 <pool>`
- server -> client: `01 05 <pool>`
- server -> client: `05 02 00 01`

The current rule set intentionally requires a **non-zero** pool value. That is why `ew-test-07` is a useful baseline but does not alert on the current pool-aware path.

---

## Validated Lua-backed rule path

### Rules

```suricata
alert tcp-pkt any any -> any any (msg:"ET MALWARE EARTHWORM SOCKS Reverse Proxy Tunnel Request Pool Store"; flow:established,to_server; dsize:6; content:"|01 04|"; startswith; byte_test:4,>,0,2; byte_extract:4,2,ew_req_pool; lua:lua/earthworm_pool_store.lua; xbits:set,ET.earthworm.request.pool.stage1,track ip_pair,expire 300; noalert; classtype:trojan-activity; sid:9000031; rev:3;)

alert tcp-pkt any any -> any any (msg:"ET MALWARE EARTHWORM SOCKS Reverse Proxy Tunnel Response Pool Match"; flow:established,to_client; xbits:isset,ET.earthworm.request.pool.stage1,track ip_pair; dsize:6; content:"|01 05|"; startswith; byte_test:4,>,0,2; byte_extract:4,2,ew_resp_pool; lua:lua/earthworm_pool_compare.lua; xbits:set,ET.earthworm.request.pool.stage2,track ip_pair,expire 300; noalert; classtype:trojan-activity; sid:9000032; rev:3;)

alert tcp-pkt any any -> any any (msg:"ET MALWARE EARTHWORM SOCKS Proxy Tunnel Post Setup Request Pool Match"; flow:established,to_client; xbits:isset,ET.earthworm.request.pool.stage2,track ip_pair; dsize:4; content:"|05 02 00 01|"; fast_pattern; classtype:trojan-activity; sid:9000033; rev:3;)
```

### Lua helper: `earthworm_pool_store.lua`

```lua
local bytevarlib = require("suricata.bytevar")
local flowintlib = require("suricata.flowint")

function init(sig)
    bytevarlib.map(sig, "ew_req_pool")
    flowintlib.register("ew_pool_req04")
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

function thread_init()
    ew_req_pool = bytevarlib.get("ew_req_pool")
    ew_pool_req04 = flowintlib.get("ew_pool_req04")
end

function match(args)
    local req_pool = ew_req_pool:value()
    if req_pool ~= nil then
        ew_pool_req04:set(req_pool)
        return 1
    end
    return 0
end
```

### Lua helper: `earthworm_pool_compare.lua`

```lua
local bytevarlib = require("suricata.bytevar")
local flowintlib = require("suricata.flowint")

function init(sig)
    bytevarlib.map(sig, "ew_resp_pool")
    flowintlib.register("ew_pool_req04")
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

function thread_init()
    ew_resp_pool = bytevarlib.get("ew_resp_pool")
    ew_pool_req04 = flowintlib.get("ew_pool_req04")
end

function match(args)
    local resp_pool = ew_resp_pool:value()
    if resp_pool ~= nil then
        local stored = ew_pool_req04:value()
        if stored ~= nil and stored == resp_pool then
            return 1
        end
    end
    return 0
end
```

## Validation shorthand

- `ew-test-08` alert
- `ew-test-09` alert
- `ew-test-10` no alert
- `ew-test-07` no alert, by design, because the current pool-aware rules require a non-zero pool
