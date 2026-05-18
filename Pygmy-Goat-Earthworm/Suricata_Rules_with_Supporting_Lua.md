# Pygmy Goat / EarthWorm Suricata Rules with Supporting Lua

These notes capture the validated pool-aware Suricata path for the Pygmy Goat / EarthWorm follow-on.

## Reference

- UK National Cyber Security Centre (NCSC), *Malware Analysis Report: Pygmy Goat*
- URL: <https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat.pdf>
- Relevant section: **pages 19-21**

## Validated Suricata rules

```suricata
alert tcp-pkt any any -> any any (msg:"ET MALWARE EARTHWORM SOCKS Reverse Proxy Tunnel Request Pool Store"; flow:established,to_server; dsize:6; content:"|01 04|"; startswith; byte_test:4,>,0,2; byte_extract:4,2,ew_req_pool; lua:lua/earthworm_pool_store.lua; xbits:set,ET.earthworm.request.pool.stage1,track ip_pair,expire 300; noalert; classtype:trojan-activity; sid:9000031; rev:3;)

alert tcp-pkt any any -> any any (msg:"ET MALWARE EARTHWORM SOCKS Reverse Proxy Tunnel Response Pool Match"; flow:established,to_client; xbits:isset,ET.earthworm.request.pool.stage1,track ip_pair; dsize:6; content:"|01 05|"; startswith; byte_test:4,>,0,2; byte_extract:4,2,ew_resp_pool; lua:lua/earthworm_pool_compare.lua; xbits:set,ET.earthworm.request.pool.stage2,track ip_pair,expire 300; noalert; classtype:trojan-activity; sid:9000032; rev:3;)

alert tcp-pkt any any -> any any (msg:"ET MALWARE EARTHWORM SOCKS Proxy Tunnel Post Setup Request Pool Match"; flow:established,to_client; xbits:isset,ET.earthworm.request.pool.stage2,track ip_pair; dsize:4; content:"|05 02 00 01|"; fast_pattern; classtype:trojan-activity; sid:9000033; rev:1;)
```

## Supporting Lua

### `earthworm_pool_store.lua`

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

### `earthworm_pool_compare.lua`

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

- `ew-test-08` -> alert
- `ew-test-09` -> alert
- `ew-test-10` -> no alert
- `ew-test-07` -> no alert
