# VolGUI

A native Rust/GPUI investigation workspace for the external Volatility 3 and vol-rs CLIs.

VolGUI runs a separately installed Volatility 3 or vol-rs engine and stores analysis results, evidence fingerprints, and bookmarks in case directories. Volatility is not bundled with the application.

## Documentation

**Download investigation** connects download origins with execution candidates and remote sockets. Choose **New analysis > Download and execution investigation**, then open **Download investigation**. Search a website or filename, select a finding, and follow its source records or bytes. The report keeps filename matches, residual process candidates and observed sockets distinct. Meterpreter TCP configurations belong to **Network**, where **Interesting Traffic** shows recovered findings, SMB and remote administration connections, recovering missing network findings when needed. Network also offers common-system-process and local/empty-endpoint filters, plus graph and sortable table views. See [the investigation flow](docs/investigation.md#download-investigation).

- [Building and running](docs/building.md)
- [Validation](docs/validation.md)
- [Case storage](docs/case-storage.md)
- [Investigation tools](docs/investigation.md)

## Source layout

- `src/ui/mod.rs` owns shared workspace state, initialization, and background event dispatch.
- `src/ui/` contains the window shell, navigation, dialogs, and actions grouped by responsibility.
- `src/ui/views/` contains workspace screens and record details.
- `src/ui/components/` contains shared data tables, artifact trees, and the hex panel.
- `src/lib/` contains application logic, including case storage, settings, result handling, and the Volatility CLI handler. `src/lib.rs` exports these modules.
- `src/lib/analysis/` contains native browser analysis, application memory text recovery, registry helpers and string search. Process mapping validation is shared by memory parsers.

Views share workspace state and call its actions. They do not run SQLite queries or CLI processes while rendering. This keeps background work and navigation consistent across views without introducing a second state synchronization layer. A separate state object per view would duplicate selection and case ownership, so the split follows rendering and action responsibilities instead.

Artifact grids, the analysis chooser, and recovered SQLite previews use GPUI Kit's native `DataTable`. Artifact grids retain background row loading and database sorting, selectable cell text, resizable columns, and double-click column fitting. Process and file hierarchies use their tree views.

With no case open, a welcome dialog requires opening or creating a case. Escape, backdrop clicks, and a close button cannot dismiss it. The sidebar offers Processes, Network, Files, Download investigation, Browser activity, Application memory, Registry, Global string search, and Bookmarks. Raw investigation artifacts remain available at the bottom.

Processes appear beneath their parents, and files are grouped by directory. Single-child folder chains share one row, stopping at branches or files. Both trees support branch expansion, collapse, search and record selection. Process searches retain ancestor branches for context. PPID and exit time remain available in record details and exports.

Run the basic **Process handles** analysis on Windows to show file handles beneath their owning processes. The **Handles** details tab shows every collected handle type for the selected PID, including registry keys, events, mutexes and sections, with paging and a collection action. Linux and macOS Lsof results also supply process file children. **Show file handles** in the process tree header hides or shows file children. Selecting a file keeps the process tree open; **Show in Files** selects it in the file tree.

The **Sidebar** toggle opens a resizable pane beside the result view. It displays recovered bytes as hex, UTF-8, UTF-16LE or UTF-16BE, or lets you inspect SQLite tables and rows. **Extract and view hex** queues extraction if contents have not been dumped yet. Extraction completion keeps the current tree open. Multiple cache variants can be inspected separately.

The basic **File and document recovery** analysis collects file inventories and attempts recovery before browsing. **Show unavailable files** in Files and Processes reveals confirmed uncached, failed and unsupported Windows file objects. Untested files remain visible. Directory pseudo-files such as `$Directory` are omitted automatically. Saved recovery outcomes retain their source and extraction diagnostics. See [file recovery](docs/investigation.md#file-and-document-recovery).

**Browser activity** recovers Edge, Firefox and Tor URLs and searches from browser process memory with PID, process role and source addresses. It also parses cached profile history and session files. Search parsing supports thirteen providers, including Search, DuckDuckGo, YouTube and Yandex. Memory strings, file handle owners and recorded history retain their distinct evidence meanings. **Registry** loads hive keys and typed values with targeted PrintKey jobs. **Global string search** scans the selected evidence file directly, including UTF-16 strings, and saves byte offsets and context. Browser and string findings support the existing bookmarks, CSV export, diagnostics and case history.

The title bar contains Back, File and View menus, and New analysis beside the window controls. Workspace and Case info are available from View.

**Application memory** scans a PID you choose. Enter a process ID and click **Scan process memory**, or select a process and choose **Scan memory for PID**. New analysis also has a visible PID field. The reader uses a virtualized hex editor with ten-digit addresses, UTF-8 byte cells, continuous scrolling and jump-to-offset navigation. Select hex or UTF-8 cells to decode text and numeric values in the right sidebar. The **Sidebar** toggle hides the decoder while keeping the hex view open. Decode and copy previews are limited to the first 64 KiB of a selection. Old edits remain searchable. Prerequisites and dumps are collected automatically and completed dumps are reused. Findings retain their source bytes and addresses, bookmarks and CSV export. See [application recovery](docs/investigation.md#application-memory).


**Network** groups IP addresses into a node graph with local and remote port labels. Endpoint selection opens all matching entries in a resizable sidebar, with process navigation and record details below. **Network investigation and correlation** is available in New analysis and in Network. It collects network and command inventories, then correlates their saved records. Credentials are included only when explicitly present in a network drive command. It does not perform a raw memory string scan. Use Global string search or Process Memory separately for memory recovery. See [network investigation](docs/investigation.md#network-investigation).
