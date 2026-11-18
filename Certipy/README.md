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

[PKINIT-U2U](PKINIT-U2U/) retains seven authentic comparison captures, a derived missing-precursor example and the packet guide. Its maintained Zeek 9.0.0 detector, zkg package and 39-case replay suite are in [Pb-22/zeek-detections](https://github.com/Pb-22/zeek-detections).

The [DCSync package](../DCSync/) remains separate because it detects directory replication through DRSUAPI rather than a Certipy authentication behavior.
