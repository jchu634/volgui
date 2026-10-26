# Virtual hex editor

The workspace creates `HexEditor::new(path, total, offset, window, cx)` after its existing
artifact lookup completes. It renders the entity and observes `SelectionChanged`
to update supplemental content. `selection()` exposes a byte range and a bounded
preview, independent of whether the user selected hex or UTF-8 cells.

The workspace continues to own artifact discovery, recovered-fragment navigation,
and the sidebar. The component owns scrolling, byte coordinates, selection,
background reads, and cache lifetime. `HexSource` retains one verified artifact
reader behind a mutex and only runs on background workers.

Two designs were considered. Extending the workspace's existing page state would
reuse its event channel, but would couple every scroll and pointer move to the
whole workspace and leave callers responsible for cache and selection ordering.
A separate GPUI entity keeps these details together and can also display extracted
files. The latter was chosen. The initial uniform-list implementation exposed
single-precision scroll limits
near the end of a 1 GiB dump. The final component lays out only visible rows on a
GPUI canvas, keeping logical scroll offsets in double precision and converting
only viewport-relative coordinates to GPUI pixels. The native scrollbar uses
a scaled full-file extent, while wheel and keyboard navigation retain byte accuracy.

Rows have sixteen hex cells and sixteen UTF-8 byte cells beneath a fixed header.
Only visible 4 KiB blocks are requested, with at most four pending reads and 64
cached blocks. Decode previews are debounced and capped at 64 KiB while the byte
selection itself can span the dump. Pending jobs retain their source and check
selection identity before publishing. Replacing the component drops its state.
Offsets refer to the dump file, not virtual process addresses. The captured bytes
are read-only.

Addresses show ten hexadecimal digits. Hover for the complete dump offset when
it exceeds forty bits. UTF-8 leading bytes show decoded characters, continuation
bytes show middle dots, and malformed sequences show replacement characters.
Selections and copied hex remain byte-based. Copying from the UTF-8 column
copies decoded text.
