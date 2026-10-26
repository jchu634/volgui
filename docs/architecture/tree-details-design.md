# Tree details in the standard DataTable

Processes, Registry and Loaded modules use a `TreeTable` delegate for the same
`DataTable` component as the other result views. Files retains its original tree.

## Usage and ownership

`render_artifact_tree(group, cx)` calls `sync_tree_table(group, cx)` and renders
`DataTable::new(&self.tree_table)`. The first column contains the tree controls,
icons and names. It is pinned on the left. The remaining columns contain formatted
record metadata and scroll horizontally on the right. The Process tree defaults
to two-thirds of the available width; Loaded modules and Registry default to one-half.
The available width is measured after layout. Native column resizing changes the
divider and preserves widths per group for the session. At least 160 pixels remain
for the detail columns.

`TreeTable` projects rows directly from `ResultTree::visible`. Expanding a branch
changes that one projection. One component owns row height, virtualization,
selection, scrollbars and column resizing, so both sides remain aligned. Tree
keyboard handling captures navigation before native table bindings change it.
The table selection maps to a node index rather than the flat query index.

Expansion state is retained for each evidence, artifact group and set of source
runs until the case closes. Query rebuilds and visibility toggles restore it by
record ID, module source and PID, or directory and registry path. Hidden branches
retain their state, and compacted directory rows retain every merged path's
identity. Expand all and Collapse all also set the default for returning branches.

`ResultTree::detail_node(i)` returns the owning process for a file handle row and
the node itself for other rows. Display columns use that source's PID, session,
thread count, process path and creation time. Clicking a handle still selects its
own record. `request_tree_rows` requests both handle records and their metadata
sources, including parents outside the viewport, through the bounded row cache.

`result_table::tree_columns` removes the name already shown in the tree. Module
columns also omit Base, LoadCount and Size, with raw fields retained in details.
Module construction still groups records by source scan and process PID, and
keeps kernel records in a separate source group.

## Decision and tradeoffs

The earlier custom tree columns duplicated table layout and resize behavior and
made the tree too narrow. A pinned hierarchy column gives the requested left tree
and right table using the standard component. Independent tree and table widgets
would need two virtual lists, matching row heights, bidirectional scroll syncing
and selection reconciliation. Pinning keeps those responsibilities in DataTable.

Tree columns preserve hierarchy order rather than sorting individual rows across
branches. The file browser does not acquire a detail table.

## Verification

Saved-result tests cover module grouping, aliases, kernel records, filtering,
branch controls and process metadata inheritance on file rows. Column tests verify
hidden module fields remain in the original records. Native checks cover the
wide pinned tree, independent horizontal detail scrolling, resizing, selection,
keyboard controls, expansion, and parent data after scrolling out of view.
