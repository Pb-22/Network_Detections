# Certipy Detection Packages

Organize Certipy related detections by the authentication or certificate behavior under investigation. Each technique keeps its captures, packet guide, and detection logic together.

## Package layout

Use this structure for each technique:

```text
Certipy/
  <technique>/
    README.md
    pcap/
      README.md
      <capture>.pcap
    Suricata/
      README.md
      <detection>.rules
```

`PKINIT-U2U` is the selected directory name for the next certificate authentication package. Its capture comparison will separate PKINIT authentication from the subsequent Kerberos user to user request used during credential recovery.

The [DCSync package](../DCSync/) remains separate because it detects directory replication through DRSUAPI rather than a Certipy authentication behavior.
