# Detector families and packet tests

families.json groups source files into detector offerings for the website. It
also identifies a ready PCAP as the first test. The source and its reference
notes come from one resolved repository commit. The website computes source
identities and capture links; authors do not maintain approval hashes or pins.

## Declare the files

Each family has a stable id, entry path, title, description and files list. File
roles are entry, required or optional. A helper remains part of its detector,
while an adapter stays explicitly optional. Grouping does not enable a script
in a package loader or change a release.

The files stay at their existing paths, and their individual reader URLs remain
available. The catalog shows the detector once. The reader offers tabs for its
files and keeps explanations attached to each original source.

## Connect explanations

Existing links within a file keep their two item form:

```json
["helper-entry", "Follow the helper"]
```

A relationship to another family file names its exact path and topic. For
example, a hypothetical source family could use:

```json
{
  "path": "scripts/example/helper.zeek",
  "topic": "helper-entry",
  "label": "Follow the helper"
}
```

The destination topic anchors its range with the existing code snippet format.
Following the relationship selects that file, highlights the target source and
opens its explanation. Return navigation restores the caller. Explain inputs,
checks, state changes and results throughout the helpers, with further links
where the flow continues into another file.

Keep meaningful topic IDs and source snippets. Blank lines or comments inserted
before the source do not require manual line updates. An unresolved topic or
relationship omits only that mapping; it does not make readable source
unavailable or require a new approval process.

## Put a PCAP first

The captures list supplies a repository, path, label, expected_notices and
provenance. The first entry is the primary test. capture_guide points to the
instructions. Use a ready file that a consumer can download or inspect without
running a generator. Keep the approved capture in a pcap directory and retain
generators as optional reproduction tools.

Separate native captures, documented derivatives and constructed fixtures.
State expected detector results rather than calling every zero result benign.
The website resolves capture URLs against the same source snapshots used in the
build; no mutable script is executed by the reader or importer.

## Complete source and original files

The reader can offer a generated complete script and an original source bundle.
The complete script expands the supported required local imports while keeping
their declaration order and module meaning. Optional adapters are not silently
enabled. Original files retain their accepted bytes. A generated convenience
copy is not another manually maintained detector implementation.
