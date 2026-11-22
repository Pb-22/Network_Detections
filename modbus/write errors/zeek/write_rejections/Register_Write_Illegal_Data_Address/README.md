# Register write rejected: Illegal Data Address

The maintained script is in [Pb-22/zeek-detections](https://github.com/Pb-22/zeek-detections/blob/main/scripts/modbus-write-illegal-data-address.zeek). The [Modbus write rejection guide](https://github.com/Pb-22/zeek-detections/blob/main/MODBUS-WRITE-REJECTIONS.md) contains matching conditions, notice fields and replay commands.

The [combined positive and negative capture](../../../pcap/Register_Write_Illegal_Data_Address__combined_positive_negative__expected_2_notices.pcap) remains in this repository. Loading this script alone against that capture produces two `ModbusWriteRejection::Register_Write_Illegal_Data_Address` notices.

The [capture manifest](../../../pcap/manifest.csv) identifies the notice type for each expected count. [SHA256SUMS](../../../pcap/SHA256SUMS) records the original capture hashes.
