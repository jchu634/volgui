# File recovery

The file browser calls `files::filter_entries` on its query worker before building either a directory tree or process file children. It returns the retained entries and recovery states for row labels. Unknown files remain visible. Confirmed empty extractions, failed attempts, and unsupported Windows file objects are hidden unless Show unavailable files is enabled. Directory pseudo-files are always omitted from these views, while the original records remain saved.

`RecoveryIndex::load(directory, document)` associates extraction outcomes with evidence, address space, and object address. It reads output metadata once, and uses ordinary output listings for runs without archived metadata. A recovered output takes precedence over an unsuccessful retry. File names alone never establish availability.

The basic File and document recovery choice collects FileScan and Handles, then defers expansion until preceding jobs finish. `files::recovery_runs` creates distinct per-object DumpFiles jobs and a native report. The report records source run and row, extraction run, and recovery status. Existing extraction, content decoding, SQLite inspection, export, and object storage continue to own the bytes. Unlabelled FileScan addresses default to virtual; the analysis supports `--physical` for older captures.

A second possible design was to run one unrestricted DumpFiles job and infer missing files from its output. That would be cheaper to launch, but it cannot establish that every scanned object was attempted. It also loses per-object failure diagnostics. Per-object jobs reuse the existing retry and provenance model, at the cost of a longer queue on large captures.

