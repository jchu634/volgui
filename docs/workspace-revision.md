# Workspace revision

Case metadata and CLI provenance remain in the case manifest. Completed scan records live in `case.sqlite`, with immutable run/row identities for annotations. Raw CLI files remain available for audit and recovery. Existing completed JSON output is imported once, on a worker, without touching the acquisition.

The result store owns search, sorting, row lookup and navigation projections. The UI asks for a lightweight ordered list of record IDs, then fetches visible rows in batches. A bounded row cache and GPUI virtual lists replace full JSON tables and per-frame filtering. A process tree uses PID/PPID relationships with cycle and missing-parent handling. Network and file browsers use lightweight virtual rows. Search requests are debounced and stale responses are discarded.

Artifact groups describe investigator tasks rather than individual plugins. Completed scans from several plugins can populate a group. Groups without results remain muted and offer an analysis picker with selected/all queue actions. OS selection belongs to the evidence and filters plugin choices. Common framework plugins remain available for every OS.

The titlebar holds the application name, separator, and File dropdown. New/open/recent cases, close case, settings and add evidence live in that menu. The welcome screen also offers case actions, and the evidence header has an add button. Settings uses a GPUI dialog. A statusbar dropdown combines queue counts, circular progress and recent analyses, with running jobs first and an inline cancel button. It replaces the recent-analysis sidebar section. The application title contains no descriptive tagline or validation-case label.

The result table fills the main pane and keeps virtual row loading while adding resize handles and both scrollbars. The details pane is below a draggable divider. Selectable field text, field copy actions, an expandable JSON view and indexed parent/child process links support record inspection. Back navigation restores page, evidence, scope, query and selection snapshots. Close case invalidates outstanding workers before releasing case ownership.

Alternatives considered: retaining full result tables behind SQLite would preserve the same UI-thread work and memory costs; replacing the native app with a web frontend would add a second runtime without addressing storage or query ownership. The revision keeps GPUI and moves result work into the store.
