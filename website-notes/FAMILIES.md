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

## Author the connection at its source

Place a relationship on the topic that contains the actual call, value handoff,
shared declaration or control transition. Give that topic a focused source
snippet. Its label explains what moves between the files or which operation the
reader should follow. For a constant or type relationship, name the shared
setting or declaration rather than calling it a function invocation.

The destination path identifies another member of the same declared family in
the same repository. The destination topic ID identifies its logical starting
point. For a helper call, anchor the function definition and its first checks,
rather than an export prototype or an unrelated section of the file. A later
operation inside that helper can have its own topic and further relationship.

Author only path, topic and label on a relationship. The website resolves the
current destination title and source ranges from that topic, then builds the
file and line labels, connection cards, tab indicators and connection selector.
The generated target object and displayed line numbers belong to the build;
they are not fields to copy into authored notes. Keep topic IDs stable when
refining prose or moving source statements.

## Worked caller and helper pair

This existing pair is from the iodine family in Pb-22/zeek-detections. The caller
lives in scripts/iodine/main.zeek, with its note in
website-notes/iodine/main.json. This topic belongs in that sidecar's topics array:

```json
{
  "id": "dns-decode",
  "title": "Require an accepted DNS wire envelope",
  "description": "dnswire(contents) returns the decoded DNS metadata. The ok guard returns immediately for an invalid envelope. Accepted metadata includes the DNS role, ID, question labels, exact question identity, type, class and decoded answer when available.",
  "ranges": [
    {"code": "local d=dnswire(contents); if (!d$ok) return;"}
  ],
  "links": [
    ["dns-dispatch", "Route the accepted DNS role"],
    {
      "path": "scripts/iodine/wire.zeek",
      "topic": "dns-header",
      "label": "Decode the UDP payload into DNS question and answer metadata"
    }
  ]
}
```

Its destination is the dns-header topic in
website-notes/iodine/wire.json. The snippet starts at the actual dnswire
definition and includes the initial envelope guards:

```json
{
  "id": "dns-header",
  "title": "Require one complete standard DNS question",
  "description": "dnswire requires a 12 byte header and QDCOUNT equal to one. It reads flags at offset two, requires opcode zero, RCODE zero and TC clear. These checks admit a standard successful, complete DNS envelope before expanding names or walking records.",
  "ranges": [
    {"code": "function dnswire(s: string): DNSWire\n{\nif (|s|<12 || u16(s,4)!=1) return [];\nlocal flags=u16(s,2);\nif ((flags/2048)%16!=0 || flags%16!=0 || (flags/512)%2!=0) return [];"}
  ],
  "links": [
    ["dns-record-count", "Bound section record counts"],
    ["dns-question", "Read the single question"]
  ]
}
```

The reader connects the caller's current source range to that helper entry.
Return restores the actual caller topic and source position. The remaining
helper topics explain record limits, question parsing and subsequent work.
These two topics illustrate the connection; they do not replace the complete
sidecars. The maintained examples are
[main.json](https://github.com/Pb-22/zeek-detections/blob/main/website-notes/iodine/main.json)
and [wire.json](https://github.com/Pb-22/zeek-detections/blob/main/website-notes/iodine/wire.json).

## Explain the whole helper

Give helpers the same detail as the entry file. Split primary ranges around
individual declarations, guards, decoding steps, field assignments, state
changes and returns. Explain the actual inputs, syntax, decision and resulting
value or state. Use separate topics for distinct operations and sparse concept
ranges for facts that genuinely span them. The operation determines explanation
length; a broad handler summary does not substitute for its individual checks.

Include further file relationships where the helper uses another family file.
A section with only local checks can keep links within its own file. Leave an
unrelated guard free of invented helper calls. Optional adapters stay explicitly
optional in their roles and relationship labels. Notice placeholders retain
ordered bindings to their exact source arguments; helpers with no Notice output
keep an empty notice object.

## Reader presentation

Detection overview opens by default. Testing, downloads, copies, source/package
details and status messages stay together in one closed disclosure. A ready
PCAP is the first testing option after that disclosure opens.

Filenames identify the tabs. Connection cards precede long explanations and
show the caller and destination portions. The active file connection selector
lists the authored relationships throughout that file, including those outside
the selected section. Notes supply the explanation and relationships; the
renderer supplies those controls and disclosure states.

## Check a notes change

1. Keep every topic ID unique within its file and every destination ID present
   in the named family member.
2. Resolve every source snippet uniquely. Use minimal before context for an
   otherwise repeated block. Confirm placement still works after adding blank
   lines or comments above the source.
3. Keep primary ranges disjoint and cover the helper's substantive operations.
   Preserve literal code, identifiers, values and Notice text.
4. Check each relationship against the actual caller and destination operation.
   Verify the selected helper range and explanation, onward links and Return to
   the correct caller. Check that links are visible before long prose, including
   the initial desktop and mobile viewport, rather than relying on automation
   to scroll a buried control into view.
5. Reconstruct each Notice template and bind its placeholders to the source
   arguments in the original order.
6. Commit changed source and matching notes together. A notes only change uses
   the normal Git publication and scheduled website refresh. No author hashes,
   commit approval pins or manual line maintenance are required.

An unplaceable snippet or relationship omits only its affected mapping. Keep
readable source and other valid explanations available while correcting it;
ordinary notes edits do not add a production approval gate.

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
