# Investigation tools

Select a memory image in the sidebar before using these tools. Results belong to
that evidence capture. Application analyses appear in the same queue and case
history as Volatility jobs, and their findings support bookmarks and CSV export.

## Browser activity

1. Choose **Browser activity**, then **Start analysis**. VolGUI
   collects processes, command lines and file candidates, recovers browser memory
   and profile files, then analyzes URLs, searches, history and saved tabs.
   GPU and utility processes are skipped. Completed dumps are reused.
2. Search for a phrase, domain or PID. Select a blue PID to open the process.
3. Select a finding to inspect its process, URL and decoded search terms or URL
   parameters. **View URL bytes** opens memory at the recorded offset.
   **Open source extraction** opens the dump job.

Memory findings can include stale strings, resources and suggestions and do not
alone prove a visit. Process dumps can occupy several GB and remain in the case.
File handle owners identify profile file owners, rather than which process
performed a search. Multiple owners appear in Related PIDs in the details.

Supported sources:

- Chromium history `urls`, `visits` and `keyword_search_terms`, including Chrome,
  Edge, Brave and Opera profiles. Visit times are converted from the Windows epoch
  to UTC. A keyword table's timestamp is labelled as the URL's last visit time.
- Firefox `moz_places` and `moz_historyvisits`, with Unix microsecond timestamps.
- Unencrypted Chromium SNSS session versions 1 and 3. The parser replays selected
  navigation indexes, navigation pruning and tab/window closure commands.
- Firefox session JSON and Mozilla LZ4 session files, using the selected history
  entry of each tab and excluding closed tabs.

Search URL parsing supports Brave, Search, DuckDuckGo, WebCrawler, Ecosia,
Excite, Rumble, YouTube, Yandex, Bing, Info, Ask and Google. Yahoo support remains
available for existing cases. Parsing uses provider hostnames, result-page paths
and query parameters, including YouTube's `search_query` and Yandex's `text`.
Spaces and percent-encoded text are decoded. Search templates, blank queries,
autocomplete endpoints and lookalike hosts are excluded. Recognized DuckDuckGo
onion result URLs are supported. Historical provider URLs remain useful even if
the service has changed since the capture.

Memory findings establish that URL bytes occur in a process's user address space.
They can include stale data, embedded resources, suggestions or prefetches. They
alone do not prove a visit, a user action or a tab open at capture time, and have
no inferred timestamp. Shared kernel mappings are excluded because they can
contain other processes' data. Only contiguous mapped user pages are joined;
unreadable gaps never become invented strings. Invalid or truncated mapping
ranges are skipped with diagnostics while other readable ranges are retained. Truncated candidates are flagged
and do not produce decoded search terms. String boundary describes whether a
byte delimiter was found; adjacent text can still be present in memory strings.
Query origin flags known automated Edge annotation URLs. Other query URLs retain
an unknown origin, so decoded terms are not presented as proof of typed input.

Memory searches with the same decoded terms or a shorter query prefix are grouped
under the longest query for the same PID, source dump, search endpoint and query
origin. Different query extensions remain separate. Tracking parameters and URL
encoding differences do not create extra rows. This grouping is case-sensitive
and does not establish which queries were submitted. Search variants in the
details retain every grouped URL, address, offset, encoding and occurrence count.
Occurrences counts the displayed URL; Grouped occurrences totals all variants.
History visits, saved tabs and non-search URLs retain their existing records.
Run Start analysis again to apply grouping to previously saved findings; completed
process dumps are reused.

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
Process scanning uses bounded buffers, an 8 KiB URL limit and at most 10,000
unique URLs per PID. Memory recovery refuses batches exceeding 128 new process
dumps. Automatic profile recovery refuses batches exceeding 512 new file objects. Extract a
specific profile's files through Files to narrow large investigations.

On 32-bit Windows mappings, the scanner conservatively uses the default 2 GiB
user range. Captures configured with a 3 GiB user split may omit URLs above that
boundary. The 64-bit user/kernel boundary is bit 47, including masked mappings.

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
