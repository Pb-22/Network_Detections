# Feed changelog

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
