# VolGUI

A native Rust/GPUI investigation workspace for the external Volatility 3 CLI.

VolGUI runs a separately installed Volatility engine and stores analysis results, evidence fingerprints, and bookmarks in case directories. Volatility is not bundled with the application.

## Documentation

- [Building and running](docs/building.md)
- [Validation](docs/validation.md)
- [Case storage](docs/case-storage.md)

## Source layout

- `src/ui.rs` owns shared workspace state, initialization, and background event dispatch.
- `src/ui/` contains the window shell, navigation, dialogs, and actions grouped by responsibility.
- `src/views/` contains the changing workspace views. Artifact tables and record details have separate modules so either can change independently.
- `src/lib/` contains the SQLite result handler and Volatility CLI handler. `src/lib.rs` keeps their existing public module paths.
- The remaining source modules define case storage, settings, analysis drafts, artifact groups, extracted files, and table formatting.

Views share workspace state and call its actions. They do not run SQLite queries or CLI processes while rendering. This keeps background work and navigation consistent across views without introducing a second state synchronization layer. A separate state object per view would duplicate selection and case ownership, so the split follows rendering and action responsibilities instead.

With no case open, a welcome dialog requires opening or creating a case. Escape, backdrop clicks, and a close button cannot dismiss it. The sidebar keeps evidence selection and a left-aligned stack of Processes, Network, Files, and Bookmarks buttons at the top, with Investigation Artifacts aligned to the bottom. The artifact tree/list browser has been removed.

The title bar contains Back, File and View menus, and New analysis beside the window controls. Workspace and Case info are available from View.
