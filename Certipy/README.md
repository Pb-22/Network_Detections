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
    Zeek script/
      <detector>.zeek
```

[PKINIT-U2U](PKINIT-U2U/) contains the tested Zeek 9.0.0 detector, seven authentic comparison captures, a derived missing-precursor example and a portable offline replay suite. Its measured 39 cases separate PKINIT authentication from linked self-targeted Kerberos U2U ticket issuance. Use the engine directory that actually supplies the detection; this package uses `Zeek script/`, not `Suricata/`.

The [DCSync package](../DCSync/) remains separate because it detects directory replication through DRSUAPI rather than a Certipy authentication behavior.
