# Modbus register write rejection PCAPs

Download a ready capture first. Each primary file below contains matching and
nonmatching test exchanges. With the named detector alone on Zeek 9.0.1, the
expected result is two matching Notices.

| Reason | First PCAP | Expected Notices |
|---|---|---:|
| Illegal Function | [Combined case](pcap/Register_Write_Illegal_Function__combined_positive_negative__expected_2_notices.pcap) | 2 |
| Illegal Data Address | [Combined case](pcap/Register_Write_Illegal_Data_Address__combined_positive_negative__expected_2_notices.pcap) | 2 |
| Illegal Data Value | [Combined case](pcap/Register_Write_Illegal_Data_Value__combined_positive_negative__expected_2_notices.pcap) | 2 |
| Server Device Failure | [Combined case](pcap/Register_Write_Server_Device_Failure__combined_positive_negative__expected_2_notices.pcap) | 2 |
| Normal polling | [Control](pcap/normal_poll.pcap) | 0 with each detector |

The maintained detector sources are in
[Pb-22/zeek-detections](https://github.com/Pb-22/zeek-detections).
Its [Modbus guide](https://github.com/Pb-22/zeek-detections/blob/main/MODBUS-WRITE-REJECTIONS.md)
gives a direct Zeek replay command for each file and the exact Notice fields.
These are constructed protocol test exchanges. The original PCAP bytes are
retained here, including the broader [capture collection](pcap/).

Generators and automated regression runners remain available for reproducing
the tests. They are optional; downloading and inspecting a PCAP does not require
running an unknown Python script.
