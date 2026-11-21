# Register write rejected: Illegal Data Value

`modbus-write-illegal-data-value.zeek` raises a notice when a Modbus responder reports Illegal Data Value (`03`) for FC06, Write Single Register, or FC16, Write Multiple Registers. FC16 is decimal 16 (`0x10`).

## Replay the combined positive and negative capture

From this directory, run:

```sh
zeek -Cr ../../../pcap/Register_Write_Illegal_Data_Value__combined_positive_negative__expected_2_notices.pcap ./modbus-write-illegal-data-value.zeek
```

Expected output: two matching notices, one for FC06 and one for FC16. This constructed capture includes successful writes and reads, a read error after a successful write, other exception reasons and other functions alongside the matching responses. Zeek writes its logs in the current working directory.

The [capture manifest](../../../pcap/manifest.csv) identifies the notice type for each expected count. Select rows for `ModbusWriteRejection::Register_Write_Illegal_Data_Value` when testing this script. [SHA256SUMS](../../../pcap/SHA256SUMS) records the capture hashes.

## Meaning

Illegal Data Value describes a request field or structure error. For example, FC16 requires a byte count twice its register quantity. A responder can report reason03 when those fields disagree. The notice records that observed reply; examining the corresponding request identifies the specific field inconsistency. Application context supplies the meaning and intended range of a stored register value.

The [MODBUS Application Protocol Specification V1.1b3](https://modbus.org/file/secure/modbusprotocolspecification.pdf), sections 6.12 and 7, defines these semantics.

## Matching conditions

The script handles Zeek's parsed `modbus_exception` event. Each matching response has:

| Field | Value |
|---|---|
| Protocol ID | `0` |
| MBAP length | `3` |
| Exception function | `0x86` for FC06 or `0x90` for FC16 |
| Exception code | `3` |

The MBAP length counts the unit ID, function code and exception code. The inspected Zeek analyzers dispatch this event from the responder branch after TCP stream reassembly. The script evaluates each parsed response as a stateless check.

## Notice output

The script writes to standard `notice.log` with this notice type:

```text
ModbusWriteRejection::Register_Write_Illegal_Data_Value
```

`msg` names the rejected function and Illegal Data Value reason. `sub` contains the transaction ID, unit ID, function code, exception code, protocol ID and MBAP length. Standard connection fields identify the client and responding device.

The Notice action is `Notice::ACTION_LOG`, with a suppression interval of `0secs`. Repeated application messages and reused transaction IDs each produce notices. Existing Modbus logging stays enabled.

## Loading all three write rejection scripts

```sh
zeek -Cr ../../../pcap/Register_Write_Illegal_Data_Value__combined_positive_negative__expected_2_notices.pcap ./modbus-write-illegal-data-value.zeek ../Register_Write_Illegal_Function/modbus-write-illegal-function.zeek ../Register_Write_Illegal_Data_Address/modbus-write-illegal-data-address.zeek
```

The combined capture produces two Illegal Data Value notices, two Illegal Function notices and two Illegal Data Address notices when all three scripts are loaded, six notices in total.

## Verification

Zeek 8.0.11 and 9.0.1 passed 216 replay checks across 100 existing cases and eight focused captures. The focused captures exercise every exception split boundary, coalesced replies, repeated transaction IDs, retransmissions, successful FC03 data containing exception byte patterns, originator markers and complete exception messages with an extra byte.

Independent specification and quality reviews passed. Twelve fresh parent replay checks passed, including focused controls and the named combined capture with this script alone and all three scripts loaded. Source hashes, packet checksums, raw notice fields and native protocol log preservation were verified.

## Script SHA256

```text
ff343f54fd21192e380d08a7161ea989ca2c5e30cc8bdbae0055135846c92e5b
```
