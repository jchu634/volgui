# Quarantined threats

The caller selects `QUARANTINE` in an `AnalysisDraft`, then uses the ordinary
case queue. The draft collects available unfiltered FileScan, Handles, PsList,
PsScan, CmdLine and ADS inputs. A deferred job recovers Defender Entries metadata
files before publishing a native report. Existing browser and download reports
can supply origin evidence. No payload restoration is needed.

## Design comparison

One option was a filtered Files tree with quarantine path rules. That can identify
quarantine containers, but cannot explain encrypted Defender metadata, execution
matches or local blocked outputs without putting analysis logic in the UI.

The selected option is a native report using the existing queue and result store.
It owns metadata decoding and correlation; the shared table, details, source
navigation, bookmarks and export work with its ordinary records. The capture and
local computer are separate values in the Scope column. Path-only findings and
local availability failures never become confirmed antivirus detections.

## Contract and module map

```rust,ignore
// analysis/quarantine.rs: bounded inventories, recovery and evidence joins.
pub const QUARANTINE: &str = "volgui.quarantine.Investigation";
pub fn recovery_runs(directory: &Path, document: &CaseSnapshot,
    evidence: &Evidence, engine: &Installation) -> Result<Vec<Run>, String>;
pub fn analyze(directory: &Path, document: &CaseSnapshot, run: &Run,
    cancel: &AtomicBool, progress: &impl Fn(String)) -> Result<(Table, String), String>;

// analysis/quarantine/defender.rs: metadata only, no payload decryption.
pub(super) fn parse(bytes: &[u8]) -> Result<Vec<Record>, String>;
```

Rows include Scope, Antivirus, Evidence status, Threat, Filename, Original path,
Quarantine path, Quarantined at, Execution evidence, PID, Origin evidence, URL,
and Sources. Source references retain run and row, plus recovered metadata file.
Only complete structurally valid Defender metadata is labelled confirmed.
Folder matches are candidates. Local blocked outputs retain the recorded reason
and are labelled unavailable, with antivirus cause unconfirmed.

Process inventory matches are candidates for the quarantined file identity.
Full command executable paths are stronger than filename matches. Command
arguments and file-handle owners do not establish execution. PsScan findings
retain their weaker status. Missing evidence means unknown, never "not run".
Downloads join on original path where comparable, otherwise filename with an
explicit weak-match label. All inputs precede the report and share its evidence.

The parser bounds section sizes, offsets, strings and counts and validates CRCs.
It decodes metadata in memory, leaving quarantined payloads isolated. Failed or
partial recovery remains a candidate with diagnostics. Individual recovery is
limited to 512 metadata file objects per run. Windows unlabelled FileScan offsets
use the existing virtual-offset default; explicit physical offsets are honoured.

The Investigation artifacts buttons become ordinary full-width navigation
buttons. Collection remains available in New analysis, and Quarantined threats
also has Start analysis. Removing the picker also removes its unused state.
Without a configured engine, Analyze collected evidence runs against saved case
records and local blocked output records, without queuing extraction jobs.

## Passive isolation updates

Opening a case, viewing Quarantined threats, completing any analysis and discovering
a newly blocked output schedule a background check of saved isolation records.
When those records or their process/origin inventories change, an internal
`--passive <fingerprint>` report updates the view through the normal result store.
Unchanged reports are reused, including after reopening a case. Passive reports
read saved data without requiring the capture file, running an engine or queuing
extractions. They take an available queue slot ahead of unrelated queued scans
and do not create a recovery barrier. Explicit analysis remains available.

Failed, cancelled and interrupted engine jobs whose diagnostics report antivirus
interference appear even if no output manifest survived. These rows name the
source analysis and status and retain its diagnostics. A missing filename stays
unknown. Ordinary permission failures and empty caches are not antivirus leads.
Defender IO failures while archiving other plugin outputs retain the output name.
Passive reports do not count as previously selected manual scans and are omitted
from case rescan requests.

## Format reference

[Fox-IT's Defender quarantine research](https://www.fox-it.com/be-en/reverse-reveal-recover-windows-defender-quarantine-forensics/)
describes independently encrypted header and metadata sections and the resource
field layout. The implementation reads those structures without restoring the
quarantined file contents.

## Validation

Synthetic encrypted metadata fixtures cover bounds, CRCs and multiple resources.
Case integration tests cover deferred recovery, process and origin match limits,
scope separation, local blocked records, cancellation, export and reopening.
Real-capture recovery depends on available cache pages and is not guaranteed.
