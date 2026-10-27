# File recovery

`files::filter_entries` builds recovery labels before either file tree is rendered. Unknown files remain visible. Disabling Show unavailable files hides confirmed empty, failed and unsupported extractions. Directory pseudo-files are omitted; original records remain stored.

`RecoveryIndex` matches outcomes by evidence, address space and object address. Successful recovery takes precedence over failed retries. Names alone do not establish availability.

Bulk recovery collects FileScan/Handles, then expands into distinct DumpFiles jobs and a native report. Each outcome retains source row, extraction run and status. Unlabelled FileScan addresses default to virtual; `--physical` supports older captures. Per-object jobs cost queue space but preserve attempts and diagnostics that unrestricted dumping cannot establish.

The native report also scans for executable-path references, limited to 10,000. References retain byte provenance without claiming file presence or recoverability.

## Process files

Background queries build lightweight trees and fetch full records for visible rows and selection. Process children join handles by PID while retaining run-local process parenting.

Selecting a file handle preserves process scope. Show in Files explicitly changes scope. Content inspection opens a matching extraction or queues DumpFiles for the object. Cache variants remain selectable independently. Stale background responses are rejected by epoch.

The shared content panel owns bounded reads, text decoding and read-only SQLite inspection. A handle does not guarantee recoverable contents. Show file handles also controls handle search/counts and persists for the session.
