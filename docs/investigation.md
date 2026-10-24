# Investigation tools

Select a memory image in the sidebar before using these tools. Results belong to
that evidence capture. Application analyses appear in the same queue and case
history as Volatility jobs, and their findings support bookmarks and CSV export.

## Browser activity

1. Choose **Browser activity**, then **Scan for files**, or run **Process handles**
   from New analysis. Wait for the scan to finish and return to Browser activity.
2. Choose **Recover browser activity**. VolGUI queues per-file extractions for
   recognized browser history and session paths, then analyzes the recovered bytes.
3. Filter the results by `Web history`, `Web search` or `Session tab`, or search
   for a URL, title, search term or profile path.

**Analyze recovered files** reparses existing extractions without requiring a
configured engine. It also works with browser files produced by other dump jobs.
**Open source extraction** on a finding opens its source job. Its Extracted files
tab lets you inspect or save the recovered database or session file.

Supported sources:

- Chromium history `urls`, `visits` and `keyword_search_terms`, including Chrome,
  Edge, Brave and Opera profiles. Visit times are converted from the Windows epoch
  to UTC. A keyword table's timestamp is labelled as the URL's last visit time.
- Firefox `moz_places` and `moz_historyvisits`, with Unix microsecond timestamps.
- Unencrypted Chromium SNSS session versions 1 and 3. The parser replays selected
  navigation indexes, navigation pruning and tab/window closure commands.
- Firefox session JSON and Mozilla LZ4 session files, using the selected history
  entry of each tab and excluding closed tabs.

Search URLs for Google, Bing, DuckDuckGo, Yahoo and Brave produce decoded search
terms. Chromium keyword records can also identify searches from custom providers.
Each finding retains its source job and cache file. Original profile paths and
owning PIDs are included when the source file scan or handle supplies them.

Session tabs describe a saved session snapshot. A historical session file, stale
cache variant or closed browser can still contain these records. They do not prove
which tabs were open at capture time, and arbitrary URL strings are not classified
as open tabs. Encrypted Chromium sessions are reported as unsupported in Run
details. Detached SQLite WAL pages are not merged. Missing or evicted pages can
prevent recovery; parser errors and partial results remain in the diagnostics.

Recovery reuses completed per-file dumps and avoids duplicate object requests.
Unlabelled Windows FileScan offsets default to virtual memory for Windows 10 and
later. Use the physical-offset button for older captures. Explicit address-space
columns and Windows handle offsets take precedence.

Browser analysis retains at most 100,000 findings, reported in diagnostics if
reached. Session parsing is limited to 32 MiB per file or decompressed session.
Automatic recovery refuses batches exceeding 512 new file objects. Extract a
specific profile's files through Files to narrow large investigations.

## Process handles

Select a process and open its **Handles** details tab. This lists all collected
object types for its PID, 100 per page. **Collect handles for this process** queues
a PID-scoped Volatility job. Click a handle to see its full fields. File handles
retain the normal extraction actions. Non-file handles do not enter the file tree.

## File contents

Select a file and enable **Contents** in the bottom bar. Use the extraction action
when its bytes have not been recovered. The pane offers:

- Hex bytes, offsets and ASCII.
- UTF-8, UTF-16LE and UTF-16BE text. Decoding is per page; malformed characters or
  characters split across pages can appear as replacement characters.
- Read-only SQLite tables, 100 rows per page, with bounded cell previews. The
  pane shows at most 100 tables and 64 columns. Save the recovered file for a full
  database inspection when these limits are exceeded.

Cache variants remain separate. Contents can be partial or unavailable when
the relevant file pages were not present in the memory capture. Text and SQLite
inspection never execute recovered files or write to the database.

## Registry

Choose **Registry**, then **Find hives** if a hive scan has not been collected.
Select a hive and choose **Read key** with an empty path to see its immediate
subkeys and typed values. Select a `Key` record and choose **Open subkey** to
descend. **Up** loads the parent. You can enter a relative path such as
`Software\Microsoft` directly.

**Read subtree** requests all descendants of the entered path. For recursive
results, enter a relative path and choose Read key before navigating immediate
children. Completed key queries are reused, including when no engine is configured.
New key reads use the source hive offset and evidence capture. Missing registry
pages can make keys or values unreadable; the engine's diagnostics are retained.

PrintKey, process memory regions/dumps and process memory maps/dumps are now in
the basic analysis chooser when the installed engine supplies those plugins.

## Global string search

Enter a literal string, optionally enable **Ignore ASCII case**, and choose
**Search evidence**. VolGUI scans the selected image in bounded chunks as UTF-8,
UTF-16LE and UTF-16BE, including matches spanning chunk boundaries. Cancellation
uses the normal queue controls. The tool runs without a Volatility installation.

Results contain encoding, byte offset, the search string and nearby context.
Offsets refer to the evidence file, not process virtual addresses. At 10,000
matches the analysis stops and records the limit in Run details. Narrow the
string to inspect additional matches. Exact Unicode matching is supported;
case-insensitive matching folds ASCII characters only.
