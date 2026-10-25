# VolGUI

A native Rust/GPUI investigation workspace for the external Volatility 3 CLI.

VolGUI runs a separately installed Volatility engine and stores analysis results, evidence fingerprints, and bookmarks in case directories. Volatility is not bundled with the application.

## Documentation

- [Building and running](docs/building.md)
- [Validation](docs/validation.md)
- [Case storage](docs/case-storage.md)
- [Investigation tools](docs/investigation.md)

## Source layout

- `src/ui.rs` owns shared workspace state, initialization, and background event dispatch.
- `src/ui/` contains the window shell, navigation, dialogs, and actions grouped by responsibility.
- `src/views/` contains the changing workspace views. Processes and files have their own tree view modules, alongside artifact tables and record details.
- `src/lib/` contains the SQLite result handler and Volatility CLI handler. `src/lib.rs` keeps their existing public module paths.
- The remaining source modules define case storage, settings, analysis drafts, artifact groups, extracted files, and table formatting.

Views share workspace state and call its actions. They do not run SQLite queries or CLI processes while rendering. This keeps background work and navigation consistent across views without introducing a second state synchronization layer. A separate state object per view would duplicate selection and case ownership, so the split follows rendering and action responsibilities instead.

Artifact grids, the analysis chooser, and recovered SQLite previews use GPUI Kit's native `DataTable`. Artifact grids retain background row loading and database sorting, selectable cell text, resizable columns, and double-click column fitting. Process and file hierarchies use their tree views.

With no case open, a welcome dialog requires opening or creating a case. Escape, backdrop clicks, and a close button cannot dismiss it. The sidebar offers Processes, Network, Files, Browser activity, Registry, Global string search, and Bookmarks. Raw investigation artifacts remain available at the bottom.

Processes appear beneath their parents, and files are grouped by directory. Single-child folder chains share one row, stopping at branches or files. Both trees support branch expansion, collapse, search and record selection. Process searches retain ancestor branches for context. PPID and exit time remain available in record details and exports.

Run the basic **Process handles** analysis on Windows to show file handles beneath their owning processes. The **Handles** details tab shows every collected handle type for the selected PID, including registry keys, events, mutexes and sections, with paging and a collection action. Linux and macOS Lsof results also supply process file children. **Show file handles** in the process tree header hides or shows file children. Selecting a file keeps the process tree open; **Show in Files** selects it in the file tree.

The **Contents** toggle opens a resizable pane beside the result view. It displays recovered bytes as hex, UTF-8, UTF-16LE or UTF-16BE, or lets you inspect SQLite tables and rows. **Extract and view hex** queues extraction if contents have not been dumped yet. Extraction completion keeps the current tree open. Multiple cache variants can be inspected separately.

**Browser activity** recovers Edge, Firefox and Tor URLs and searches from browser process memory with PID, process role and source addresses. It also parses cached profile history and session files. Search parsing supports thirteen providers, including Search, DuckDuckGo, YouTube and Yandex. Memory strings, file handle owners and recorded history retain their distinct evidence meanings. **Registry** loads hive keys and typed values with targeted PrintKey jobs. **Global string search** scans the selected evidence file directly, including UTF-16 strings, and saves byte offsets and context. Browser and string findings support the existing bookmarks, CSV export, diagnostics and case history.

The title bar contains Back, File and View menus, and New analysis beside the window controls. Workspace and Case info are available from View.
