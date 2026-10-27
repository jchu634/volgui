# Download investigation

Choose Download and execution investigation in New analysis, then inspect findings in Download investigation. Sources link to records, bytes, processes and PID-filtered Network views.

`analysis::downloads` owns source selection, origin parsing, filename/path matches, residual process recovery and socket joins. Deferred recovery queues targeted browser-profile extractions before native parsing. Findings use the ordinary queue, immutable result store, bookmarks and exports.

Only preceding completed runs from the same evidence contribute. Rows retain source run/row IDs and match rules; byte findings retain offsets, encoding and coverage. Chromium parsing preserves ordered download URL chains and optional tab/referrer fields. Browser-memory URLs remain separately labelled leads.

Residual process recovery requires a supported Windows x64 layout validated against multiple process records. Carved objects remain candidates. Missing owners stay unknown, filename matches do not prove execution, and ports do not establish a reverse shell. Meterpreter configurations belong to Network; historical rows retain their original provenance there.

A separate report keeps download correlation out of browser rendering and reuses case navigation and storage. Per-profile recovery avoids dumping every browser process. Acquisition scanning requires a sequential read and bounds its findings.

Tests cover renamed downloads, URL chains, schema variation, ambiguous PIDs, evidence boundaries, cancellation, persistence and export. See [Validation](../validation.md) for capture checks.
