# Website reference notes

These files accompany the detector sources used by zeek.brimerica.com. They
contain explanations and source relationships, not executable Zeek code. The
website retrieves each source and its notes from the same repository commit.

The notes mirror the full source path, with .json replacing its suffix. For
example, pe-disguise/Zeek/main.zeek uses
pe-disguise/Zeek/main.json beneath this directory. The EarthWorm Markdown source
uses Earthworm/Zeek_Script.json; its anchors refer to the extracted Zeek code.

Topics keep stable IDs and exact source snippets. The importer locates those
snippets when it builds the reader, so inserting blank lines does not require
manual line numbers. Notice argument references use the source line and exact
argument text. Missing or ambiguous mappings omit only the affected explanation;
readable source and valid callouts remain available.

See [detector families and packet tests](FAMILIES.md) for file roles, links into
helpers, complete source downloads and the primary ready PCAP. families.json
supplies the offerings in this repository. The first capture is a direct test
file; generators stay secondary.

No author maintained source hash, commit approval or publication fingerprint is
required. Changing these notes does not change detector behavior or enable a
sensor policy.
