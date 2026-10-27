# Download investigation

Choose Download and execution investigation in New analysis, then inspect findings in Download investigation. Sources link to records, bytes, processes and PID-filtered Network views.

`analysis::downloads` owns source selection, origin parsing, filename/path matches, residual process recovery and socket joins. Deferred recovery queues targeted browser-profile extractions before native parsing. Findings use the ordinary queue, immutable result store, bookmarks and exports.

Queuing adds every missing unfiltered source inventory ahead of the report and reuses completed results or preceding queued and running jobs for the same evidence. Unsupported prerequisites prevent queuing. Recovery and execution fail when required inventories are missing or failed. Only preceding completed runs from the same evidence contribute. Rows retain source run/row IDs and match rules; byte findings retain offsets, encoding and coverage. Chromium parsing preserves ordered download URL chains and optional tab/referrer fields. Browser-memory URLs remain separately labelled leads.

Executable URL leads require a single HTTP or HTTPS URL with a supported executable suffix in its last path segment. A `.com` suffix alone is excluded because website names also use it. Recorded Chromium downloads and NTFS origins still retain `.com` files. URL lists are excluded, and URL leads remain labelled as leads even when a process filename matches. The Download URL column fills unused table width until manually resized.

Residual process recovery requires a supported Windows x64 layout validated against multiple process records. Carved objects remain candidates. Missing owners stay unknown, filename matches do not prove execution, and ports do not establish a reverse shell. Meterpreter configurations belong to Network; historical rows retain their original provenance there.

Damaged process records with sufficient surviving identity fields are retained as
[partial matches](partial-matches-design.md). They remain hidden by default,
preserve failed validation checks, and never establish socket ownership.

A separate report keeps download correlation out of browser rendering and reuses case navigation and storage. Per-profile recovery avoids dumping every browser process. Acquisition scanning requires a sequential read and bounds its findings.

Tests cover renamed downloads, URL chains, schema variation, ambiguous PIDs, evidence boundaries, cancellation, persistence and export. See [Validation](../validation.md) for capture checks.
