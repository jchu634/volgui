# Partial matches

`Settings::show_partial_matches` is a global display preference, defaulting to
false for new and existing settings. View > Show partial matches and the Settings
checkbox persist it immediately. It does not change external engine options.

Producers opt in per record with `Partial match: true`, `Partial match kind`, and
`Validation failures`. The UI never guesses partial status from a finding's name
or from a run's Warning status. This first implementation covers residual process
recovery in Download and execution investigation. Other parsers are unchanged.

## Process recovery

The scanner reads acquisition chunks with overlap, searches for exact image names,
and subtracts the supported EPROCESS image-name offset. Eight-byte fields are
decoded as little-endian integers. PID, parent PID, creation and exit times and the
terminated image name must remain plausible. An intact candidate also requires
the expected process header, page-aligned directory-table base and dispatcher
links.

A damaged candidate can fail those leading-field checks only when both surviving
active-process pointers are aligned kernel addresses. Failed checks, parsed values
and acquisition offsets are retained. This is a bounded heuristic, not validation
of the linked records or proof of execution. Both classes require a layout
corroborated by at least five intact inventory identities; partial candidates
cannot corroborate a layout. Partial and intact candidates have separate limits,
and intact copies take precedence for the same identity.

Partial candidates are collected regardless of display preference so toggling
visibility does not require another scan. Older saved reports must be rerun once.
The unresolved download origin remains present when only a partial process matches.
Partial PIDs never receive socket joins, command-line enrichment, process identity
merges, inherited parents or file handles.

## Presentation and persistence

General queries and hierarchy queries exclude partial records unless explicitly
requested. Raw run tables remain complete. CSV exports using a filtered query
respect that query's preference and retain partial metadata when included.

Tables, tree rows, network occurrences and nodes containing partial observations
use muted amber with dark text. Table rows paint a continuous background behind
cell padding. The title bar shows the global mode beside the case name. Details
use a compact Partial Match badge beside the bold item name, with failed checks
and interpretation limits in its tooltip. Network nodes mean "contains partial matches" and may also represent
intact entries. No existing incomplete network finding is reclassified.

The Processes tree projects partial process findings from download reports for the
same evidence as isolated roots. Their provenance continues to identify the
original report row. A tentative PID cannot attach itself to the validated
hierarchy or assign file ownership. Original source cases are never rewritten by
this projection.
