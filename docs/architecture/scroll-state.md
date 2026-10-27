# Session scroll state

`Workspace` owns `SessionScroll` in `src/ui/scroll_state.rs`. Nothing in this state is serialized. A new workspace starts empty, and opening or closing a case clears the state and navigation history.

## Ownership

Individual pages use `scroll_state.page(ScrollArea::Analyses, content)` to retain a handle while keeping the content at its natural height and the scrollbar over the viewport. Smaller scroll regions ask for a handle with `scroll_state.area`. Detail panes use the record ID and detail tab as their key. Plugin help and network navigation also have separate handles.

Result browsers share table entities across artifact groups. Keeping one handle per table would make unrelated views share a position. Keeping entire table entities per result scope would retain delegates, selection state and subscriptions unnecessarily. Instead, result scopes save offset snapshots keyed by evidence, artifact group and sorted run IDs.

## Navigation and loading

`set_scope` calls `remember_result_scroll` before clearing the old results. It then calls `prepare_result_scroll` for the destination. Back entries also carry a `ResultPosition`, alongside the existing query, filters and selection.

Restoration waits until result and network loading finish. Each table restores after its layout and selection have been synchronized, and cancels queued row and column scrolling that would otherwise override the saved offset. A hidden table keeps its snapshot pending until it is displayed. The file tree and network graph restore their offsets in the workspace render, with another render requested for graph virtualization.

## Verification

```powershell
cargo test --bin volgui scroll_state::tests
cargo check --all-targets
```

The tests check independent record and tab positions, fresh-session reset, result scope isolation and cancellation of queued list scrolling.

For a desktop smoke check, scroll a populated result table vertically and horizontally, switch artifact groups, and return. Repeat with the file tree, Network graph and table, analysis history, bookmarks and case information. Check Back after selecting another result. Restart the application and confirm the views start at their initial positions.
