# EarthWorm Suricata Rules

These rules are based on the current EarthWorm lab PCAPs and the UK National Cyber Security Centre (NCSC) *Pygmy Goat* malware analysis.

## Reference

- UK National Cyber Security Centre (NCSC), *Malware Analysis Report: Pygmy Goat*
- URL: <https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat.pdf>
- Relevant pages:
  - **Page 19**: `01 01` client request
  - **Page 20**: `01 02` server response, `01 03` assign pool number, `01 04` tunnel request, `01 05` tunnel response

## Notes

- In **Suricata-Bench**, paste each rule on **one line**.
- These rules currently use:
  - **flowbits** for the setup-stage chain
  - **flowbits** for the request-stage chain
- The rules use:
  - `depth`
  - `dsize`
  - directionality
  - staged bit-setting
- `01 03` is kept as optional corroboration, not as the required alert condition.

---

## Group 1: Setup Stage Control Sequence

### Logic

- `01 01` sets the first setup-stage bit
- `01 02` checks that bit and alerts
- `01 03` is optional continuation/corroboration

### Rules

```suricata
alert tcp any any -> any any (msg:"EARTHWORM setup stage marker 01 01"; flow:established,to_server; content:"|01 01|"; depth:2; dsize:6; flowbits:set,ew.setup.stage1; flowbits:noalert; classtype:trojan-activity; sid:9906001; rev:4;)

alert tcp any any -> any any (msg:"EARTHWORM Setup Stage Control Sequence"; flow:established,to_client; flowbits:isset,ew.setup.stage1; content:"|01 02|"; depth:2; dsize:6; flowbits:set,ew.setup.confirmed; classtype:trojan-activity; metadata:confidence high, deployment Perimeter, affected_product Any; sid:9906002; rev:4;)

alert tcp any any -> any any (msg:"EARTHWORM setup stage continuation 01 03"; flow:established,to_client; flowbits:isset,ew.setup.confirmed; content:"|01 03|"; depth:2; dsize:6; flowbits:noalert; classtype:trojan-activity; sid:9906003; rev:4;)
```
## Group 2: Post-Setup Request Stage SOCKS Sequence

### Logic

- `01 04` sets the first request-stage bit
- `01 05` checks that bit and promotes the request-stage state
- `05 02` 00 01 checks the promoted state and alerts

```suricata

alert tcp any any -> any any (msg:"EARTHWORM request stage marker 01 04"; flow:established,to_server; content:"|01 04|"; depth:2; dsize:6; flowbits:set,ew.request.stage1; flowbits:noalert; classtype:trojan-activity; sid:9906004; rev:3;)

alert tcp any any -> any any (msg:"EARTHWORM request stage marker 01 05"; flow:established,to_client; flowbits:isset,ew.request.stage1; content:"|01 05|"; depth:2; dsize:6; flowbits:set,ew.request.stage2; flowbits:noalert; classtype:trojan-activity; sid:9906005; rev:3;)

alert tcp any any -> any any (msg:"EARTHWORM Post Setup Request Stage SOCKS Sequence"; flow:established,to_client; flowbits:isset,ew.request.stage2; content:"|05 02 00 01|"; depth:4; dsize:4; classtype:trojan-activity; metadata:confidence medium, deployment Perimeter, affected_product Any; sid:9906006; rev:3;)
```
### Interpretation
#### Type 1: Setup Stage Control Sequence
This is the high-confidence detection for the initial EarthWorm control handshake.
#### Type 2: Post-Setup Request Stage SOCKS Sequence
This is the medium-confidence detection for actual SOCKS tunnel use after setup.
