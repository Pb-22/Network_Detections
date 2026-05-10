# EarthWorm draft detections
# Built from observed lab traffic on 2026-05-09.
# These are draft rules and should be tuned against more PCAPs before wider use.
# Suricata-Bench paste note: paste each rule on a single line in the custom rule box.
# Multi-line pasted rules can parse incorrectly in that UI path.
#
# Public protocol-grounding reference:
# UK National Cyber Security Centre (NCSC), Malware Analysis Report: Pygmy Goat,
# pages 19-20 from https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat.pdf
# The report maps the EarthWorm handshake/tunnel sequence as:
#   01 01 = client request (page 19)
#   01 02 = server response (page 20)
#   01 03 = assign pool number (page 20)
#   01 04 = tunnel request (page 20)
#   01 05 = tunnel response (page 20)
#
# Current directionality from the clean lab PCAPs:
#   01 01 = client -> server
#   01 02 / 01 03 = server -> client
#   01 04 = client -> server
#   01 05 / 05 02 00 01 = server -> client
#
# Setup-stage sequence is tracked with flowbits because it occurs on a single
# control connection. The 01 03 continuation is kept as optional corroboration,
# not as a required alert condition.


# ============================================================================
# Group 1: Setup stage control sequence 
# ============================================================================

alert tcp any any -> any any (msg:"EARTHWORM setup stage marker 01 01"; flow:established,to_server; content:"|01 01 00 00 00 00|"; dsize:6; flowbits:set,ew.setup.stage1; flowbits:noalert; classtype:trojan-activity; sid:9906001; rev:3;)

alert tcp any any -> any any (msg:"EARTHWORM Setup Stage Control Sequence"; flow:established,to_client; flowbits:isset,ew.setup.stage1; content:"|01 02 00 00 00 00|"; dsize:6; flowbits:set,ew.setup.confirmed; classtype:trojan-activity; metadata:confidence high, deployment Perimeter, affected_product Any; sid:9906002; rev:3;)

alert tcp any any -> any any (msg:"EARTHWORM setup stage continuation 01 03"; flow:established,to_client; flowbits:isset,ew.setup.confirmed; content:"|01 03 00 00 00 00|"; dsize:6; flowbits:noalert; classtype:trojan-activity; sid:9906003; rev:3;)

# ============================================================================
# Group 2: Post-setup request stage SOCKS sequence
# ============================================================================

alert tcp any any -> any any (msg:"EARTHWORM request stage marker 01 04"; flow:established,to_server; content:"|01 04 00 00 00 00|"; dsize:6; xbits:set,ew.request.stage1,track ip_pair,expire 300; noalert; classtype:trojan-activity; sid:9906004; rev:2;)

alert tcp any any -> any any (msg:"EARTHWORM request stage marker 01 05"; flow:established,to_client; xbits:isset,ew.request.stage1,track ip_pair; content:"|01 05 00 00 00 00|"; dsize:6; xbits:set,ew.request.stage2,track ip_pair,expire 300; noalert; classtype:trojan-activity; sid:9906005; rev:2;)

alert tcp any any -> any any (msg:"EARTHWORM Post Setup Request Stage SOCKS Sequence"; flow:established,to_client; xbits:isset,ew.request.stage2,track ip_pair; content:"|05 02 00 01|"; dsize:4; classtype:trojan-activity; metadata:confidence medium, deployment Perimeter, affected_product Any; sid:9906006; rev:2;)
