# File recovery

The file browser calls `files::filter_entries` on its query worker before building either a directory tree or process file children. It returns the retained entries and recovery states for row labels. Unknown files remain visible. Show unavailable files defaults to enabled; disabling it hides confirmed empty extractions, failed attempts, and unsupported Windows file objects. Directory pseudo-files are always omitted from these views, while the original records remain saved.

`RecoveryIndex::load(directory, document)` associates extraction outcomes with evidence, address space, and object address. It reads output metadata once, and uses ordinary output listings for runs without archived metadata. A recovered output takes precedence over an unsuccessful retry. File names alone never establish availability.

The extended File and document recovery choice collects FileScan and Handles, then defers expansion until preceding jobs finish. `files::recovery_runs` creates distinct per-object DumpFiles jobs and a native report. The report records source run and row, extraction run, and recovery status. Existing extraction, content decoding, SQLite inspection, export, and object storage continue to own the bytes. Unlabelled FileScan addresses default to virtual; the analysis supports `--physical` for older captures.

A second possible design was to run one unrestricted DumpFiles job and infer missing files from its output. That would be cheaper to launch, but it cannot establish that every scanned object was attempted. It also loses per-object failure diagnostics. Per-object jobs reuse the existing retry and provenance model, at the cost of a longer queue on large captures.


The native report also scans acquisition bytes for executable-path references,
with a 10,000-reference limit. These retain byte provenance and do not establish
file presence or recoverability.

## Process file integration

The workspace queries SQLite on background threads, builds lightweight trees, and fetches complete records only for visible rows and selection. Selection normally switches to the selected record's analysis when it is outside the current scope. Process handle children need to retain that scope instead.

Selecting a file under a process inspects the handle in place. Show in Files changes the scope explicitly and selects the same saved record. Hex content reads a matching per-file extraction, or queues DumpFiles from the selected file object. Completion retains the source selection. Extracted cache variants are selectable independently.

`ResultTree::processes_with_files(entries, files, matches)` joins lightweight entries by PID. The caller selects the latest handle run for the current evidence, and the existing process builder retains run-local parenting. Nodes identify processes, files, and directories explicitly.

`completed_dump(case, record, physical)` resolves an extraction by source evidence
and file-object arguments. Background actions reject stale responses with an epoch.
Both trees share extraction and content inspection. The virtual reader's bounded
reads, selection and cache ownership are described in [the hex editor design](hex-editor-design.md).

The chosen design extends the existing tree and details pane. A separate process-file browser would duplicate selection, extraction, and navigation state. Eagerly embedding file bytes in tree records would make large captures expensive and mix saved metadata with extraction output. We accept a separate extraction step because a file handle does not guarantee cached contents exist in the capture.

The content sidebar follows the selected file independently of record details.
Show file handles controls whether process queries include handle runs; disabling
it also excludes those handles from search and counts. The preference lasts for
the workspace session.
