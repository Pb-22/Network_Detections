# Register write rejected: Server Device Failure

`modbus-write-server-device-failure.zeek` raises a notice when a Modbus responder reports Server Device Failure (`04`) for FC06, Write Single Register, or FC16, Write Multiple Registers. FC16 is decimal 16 (`0x10`).

## Replay the combined positive and negative capture

From this directory, run:

```sh
zeek -Cr ../../../pcap/Register_Write_Server_Device_Failure__combined_positive_negative__expected_2_notices.pcap ./modbus-write-server-device-failure.zeek
```

Expected output: two matching notices, one for FC06 and one for FC16. This constructed capture includes successful reads and writes, a read error after a successful write, other exception reasons and other functions alongside the matching responses. Zeek writes its logs in the current working directory.

The [capture manifest](../../../pcap/manifest.csv) identifies the notice type for each expected count. Select rows for `ModbusWriteRejection::Register_Write_Server_Device_Failure` when testing this script. [SHA256SUMS](../../../pcap/SHA256SUMS) records the capture hashes.

## Meaning

Server Device Failure is the responder's report of an unrecoverable error while attempting the requested operation. The notice records the reply and its connection and protocol fields. Device diagnostics and process measurements establish the underlying cause and operational effects.

The [MODBUS Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf), section 7, defines this exception.

## Matching conditions

The script handles Zeek's parsed `modbus_exception` event. Each matching response has:

| Field | Value |
|---|---|
| Protocol ID | `0` |
| MBAP length | `3` |
| Exception function | `0x86` for FC06 or `0x90` for FC16 |
| Exception code | `4` |

The MBAP length counts the unit ID, function code and exception code. The inspected Zeek analyzers dispatch this event from the responder branch after TCP stream reassembly. The script evaluates each parsed response as a stateless check.

## Notice output

The script writes to standard `notice.log` with this notice type:

```text
ModbusWriteRejection::Register_Write_Server_Device_Failure
```

`msg` names the rejected function and Server Device Failure reason. `sub` contains the transaction ID, unit ID, function code, exception code, protocol ID and MBAP length. Standard connection fields identify the client and responding device.

The Notice action is `Notice::ACTION_LOG`, with a suppression interval of `0secs`. Repeated application messages and reused transaction IDs each produce notices. Existing Modbus logging stays enabled.

## Loading all four write rejection scripts

```sh
zeek -Cr ../../../pcap/Register_Write_Server_Device_Failure__combined_positive_negative__expected_2_notices.pcap ./modbus-write-server-device-failure.zeek ../Register_Write_Illegal_Function/modbus-write-illegal-function.zeek ../Register_Write_Illegal_Data_Address/modbus-write-illegal-data-address.zeek ../Register_Write_Illegal_Data_Value/modbus-write-illegal-data-value.zeek
```

The combined capture produces two notices for each script when all four scripts are loaded, eight notices in total.

## Verification

Zeek 8.0.11 and 9.0.1 passed 216 replay checks across 100 existing cases and eight focused captures. The focused captures exercise every exception split boundary, coalesced replies, repeated transaction IDs, retransmissions, successful FC03 data containing exception byte patterns, originator markers and complete exception messages with an extra byte.

Independent specification and quality reviews passed. Twelve fresh parent replay checks passed, including focused controls and the named combined capture with this script alone and all four scripts loaded. Source hashes, packet checksums, raw notice fields and native protocol log preservation were verified.

## Script SHA256

```text
8d35a1479a789cb9a5c37155c0a1d03b6bc7c8e36b33ac4d68ab4fbfb7ce5bf3
```
