# Feed changelog

## November 25, 2026

* Aligned the source identifier and installation examples to `pb-22/open`.
* Recorded the merged SID allocation and an 8.0.8 compatibility baseline in the index entry.
* Updated the generated feed status comment and refreshed all ten aggregate replay results against the exact file.
* Preserved all six signatures and the existing download URL.

## 2026-11-18 — WMI combined recovery inhibition

- Added standalone SID `9955010` revision 7 to the six-rule subscription feed, replacing private local SID `1000209` without changing matching logic.
- Added the complete Markdown rule file, visually wrapped HTML copy, 41 positive/negative captures, exact-rule replay results and checksums under `WMI/T1490-Inhibit-System-Recovery/`.
- Replayed the six-rule aggregate against existing feed fixtures and combined-action, split-action and wrong-interface controls.
- Preserved the matching wrong-interface negative and constructed-capture provenance. BPFDoor remains disabled; DCSync and Lua-backed EarthWorm remain standalone.

## 2026-11-17 — WMI command-output encoding

- Added standalone SID `9955009` revision 12 and included it in the five-rule subscription feed.
- Added the WMI detection guide, sixteen separate captures, combined replay capture, case map, and file hashes.
- Replayed the full feed against the retained RedFlick, Sliver, and CAV3RN fixtures and the authentic and combined WMI captures.
- Preserved the observed wrong-interface result in the WMI comparison table. BPFDoor `9955008` remains disabled and outside the aggregate.

## 2026-11-17 — maintainer-authorized SID conversion

- Converted the remaining independent repository rules to SIDs `9955000-9955007`; retained disabled-by-default BPFDoor SID `9955008`.
- Published the repository-wide map in `feed/sid-map.csv`. Detection options are unchanged; DCSync also receives the approved Possible DCSync message.
- Renumbered the four aggregate-feed Sliver/CAV3RN rules to `9955000-9955003` and removed the superseded RedFlick copy now published by ET Open.
- Kept DCSync and the Lua-backed EarthWorm groups in their existing individual directories rather than silently expanding aggregate-feed dependencies.
- Range use is authorized by the registry maintainer; registry PR merge and OISF index listing remain separate steps.

## Candidate before SID registration

- Created the deterministic `pb22/open` candidate feed.
- Added five independently maintained rules: RedFlick DNSObserver HTTP check in, Sliver age and minisign hunting, and three CAV3RN DNS branch rules.
- Excluded rules already published under ET Open SIDs.
- Added BSD-3-Clause feed licensing, checksum generation, CI validation, SID policy, and machine readable replay results.
- Assigned temporary local use SIDs `1000201-1000205`; all must be replaced after public SID allocation.
