# Process files and hex content

The workspace queries SQLite on background threads, builds lightweight trees, and fetches complete records only for visible rows and selection. Selection normally switches to the selected record's analysis when it is outside the current scope. Process handle children need to retain that scope instead.

Selecting a file under a process inspects the handle in place. Show in Files changes the scope explicitly and selects the same saved record. Hex content reads a matching per-file extraction, or queues DumpFiles from the selected file object. Completion retains the source selection. Extracted cache variants are selectable independently.

`ResultTree::processes_with_files(entries, files, matches)` joins lightweight entries by PID. The caller selects the latest handle run for the current evidence, and the existing process builder retains run-local parenting. Nodes identify processes, files, and directories explicitly.

`completed_dump(case, record, physical)` resolves an extraction by source evidence and file-object arguments. `HexPage::read(path, offset)` returns at most 256 bytes plus file size. Workspace actions own background reads and reject stale results with an epoch. Both trees share the separate hex renderer and file extraction actions.

The chosen design extends the existing tree and details pane. A separate process-file browser would duplicate selection, extraction, and navigation state. Eagerly embedding file bytes in tree records would make large captures expensive and mix saved metadata with extraction output. We accept a separate extraction step because a file handle does not guarantee cached contents exist in the capture.

The Hex toggle in the bottom status bar controls an independent hex pane to the right of the results. The details pane stays below both panes and retains its active tab. Hex has its own scrolling and extraction controls, and follows the selected file. The process header's Show file handles checkbox controls whether queries include handle runs; turning it off also excludes handles from search and result counts. The preference lasts for the workspace session.
