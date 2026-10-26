# Download investigation

## Problem and traced flow

The chooser builds an `AnalysisDraft`, expands it to engine and native `Run`s,
and saves them in the case queue. Recovery analyses are queue barriers. The
workspace expands deferred jobs before execution. `analysis::execute` writes
native results through `Case::finish` to the same SQLite record store as engine
results. Artifact groups select these saved results; rendering never scans memory
or queries SQLite directly.

Browser activity currently recovers visits, searches and URL strings, but omits
download tables and NTFS download origin streams. Process lists can omit exited
processes, while sockets can have missing owners. Neither view owns the complete
download-to-execution question.

## Usage

Choose New analysis > Download and execution investigation. Open Download
investigation, search a filename or website, then select a finding. Read the
download, process and connection evidence together. Open each source row, inspect
the acquisition bytes, navigate to the PID or filter Network by PID. Missing
evidence remains visible. A socket or a filename match does not establish malware.

```rust,ignore
draft.selected.insert(analysis::DOWNLOADS.into());
let runs = draft.prepare_in_case(engine, evidence, case)?;
// At the queue barrier, recover browser profile files using completed inventories.
let runs = analyses::prepare_download_recovery(case, engine, run)?;
// The native report owns parsing, correlation, limits and provenance.
let outcome = analysis::execute(directory, snapshot, run, cancel, progress);
```

## Shape

`analysis::downloads` owns source selection, Zone.Identifier parsing, exact
filename/path matching, residual process checks and connection joins. It returns
ordinary immutable records rather than another persisted model. Each joined row
retains source run/row identifiers and the match rule. Native byte findings retain
acquisition offsets, encoding and coverage. Only preceding completed runs from
the same evidence can contribute.

The browser parser also reads Chromium download records, their ordered URL
chains and optional tab/referrer fields. Download investigation recovers profile
files before parsing them, without requiring all browser process dumps. Existing
browser memory findings remain useful as explicitly labelled URL leads.

Residual process recovery supports a known Windows x64 EPROCESS layout only
after matching multiple independent process inventory records, including their
PID, name and creation timestamp. A carved copy is a candidate, not proof that
the process was active at acquisition. Validated Meterpreter TCP configurations belong to Network. The download parser
scans only for residual process candidates; it no longer emits standalone raw
connection text. Historical configuration rows appear in Network with their
original provenance and are excluded from the download presentation.

## Synthesis decision

Compared two structures locally. Extending Browser activity would require its
URL/search table and browser PID to also represent payload PIDs and sockets. That
leaks correlation rules into rendering and makes browser ownership ambiguous.
A separate report group reuses the queue, record table, navigation, bookmarks
and exports while keeping the correlation policy in one native analysis.
The referenced how/arena skills and the architect skill's default runner models
are unavailable in this session, so no arena result is claimed.

## Tradeoffs accepted

- Filename equality creates a labelled candidate; exact paths give stronger evidence.
- Missing socket owners remain missing. Ports never establish reverse-shell behavior.
- Acquisition scanning costs one sequential read and retains bounded findings.
- Residual process layouts outside the validated profile need ordinary engine results.

## Verification

Test renamed downloads, URL chains, schema variation, ambiguous PIDs, source
boundaries, evidence separation, cancellation, persistence and CSV export. Exercise
the chooser and report against the supplied capture in a separate validation case.
