# Register write rejected: Illegal Function

`modbus-write-illegal-function.zeek` raises a notice when a Modbus responder rejects a register write with exception `01`, Illegal Function.

The detector covers FC06, Write Single Register, and FC16, Write Multiple Registers. FC16 is decimal 16 (`0x10`).

## Matching conditions

The script handles Zeek's parsed `modbus_exception` event. Each matching response has:

| Field | Value |
|---|---|
| Protocol ID | `0` |
| MBAP length | `3` |
| Exception function | `0x86` for FC06 or `0x90` for FC16 |
| Exception code | `1` |

The MBAP length counts the unit ID, function code and exception code. The inspected Zeek analyzers dispatch this event from the responder branch after TCP stream reassembly. The script evaluates each parsed response as a stateless check.

## Notice output

The detection writes to standard `notice.log` with this notice type:

```text
ModbusWriteRejection::Register_Write_Illegal_Function
```

`msg` names the rejected function and exception. `sub` contains the transaction ID, unit ID, function code, exception code, protocol ID and MBAP length. Standard connection fields identify the client and responding device.

The Notice action is `Notice::ACTION_LOG`, with a suppression interval of `0secs`. Separate parsed responses produce separate notices, including repeated transaction IDs and coalesced messages. Existing Modbus logging stays enabled.

## Replay the combined positive and negative capture

From this directory, run:

```sh
zeek -Cr ../../../pcap/Register_Write_Illegal_Function__combined_positive_negative__expected_2_notices.pcap ./modbus-write-illegal-function.zeek
```

The combined capture produces two matching notices, one for FC06 and one for FC16. It includes normal traffic and other error cases alongside the matching responses. Zeek writes its logs in the current working directory.

The [capture manifest](../../../pcap/manifest.csv) lists the companion PCAPs, their notice types, expected counts on Zeek 8.0.11 and 9.0.1, and SHA256 values. Select rows for `ModbusWriteRejection::Register_Write_Illegal_Function` when testing this script. [SHA256SUMS](../../../pcap/SHA256SUMS) supports direct file verification from the PCAP directory:

```sh
sha256sum -c SHA256SUMS
```

## Verification

The 100 constructed capture cases passed on Zeek 8.0.11 and 9.0.1: 200 replay checks, followed by a separate 200-check unittest run. An independent repeat of 21 cases on both engines passed 42 further checks.

The cases cover exception messages split at every byte boundary, coalesced responses, repeated transaction IDs, identical application messages, TCP retransmission, reordered segments and malformed lengths. Successful FC03 replies containing exception-like register bytes stay quiet. The explicit length check also excludes complete length-4 exception messages accepted by the tested native parsers.

Native log comparisons preserved the existing protocol output. The detector emits standard notices and keeps its matching logic stateless.

## References

- [Modbus application protocol specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), sections 6.6, 6.12 and 7.
- [Zeek Modbus events](https://docs.zeek.org/en/v9.0.1/scripts/base/bif/plugins/Zeek_Modbus.events.bif.zeek.html).

## Script SHA256

```text
0de1f7dfc921292c1e90a75514cc6a58ade774d768ab7cf9b3143371253c2fbb
```
