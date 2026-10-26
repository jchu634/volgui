# Investigation tools

## Download investigation

1. In **New analysis**, select **Download and execution investigation** for Windows evidence. It collects available PsList, PsScan, CmdLine, DLL paths, PsXView, FileScan, ADS, NetScan and NetStat. Existing completed unfiltered inventories are reused. Browser profile files are recovered after inventories finish, when DumpFiles is available.
2. Open **Download investigation** and search a website or filename. The grid shows the local filename, website and download URLs, matching process PID and owned remote sockets. The selected row's details contain the match rule, timestamps, paths and source links. Chromium download targets, redirects and referrers are preserved; the browser's opened flag is not treated as execution evidence.
3. Select **Download source**, **Process source**, **Command line source** or **Socket source** to inspect the original record. **Residual process bytes** opens the acquisition at a recovered process structure. **Network for PID** uses an exact `pid:<number>` search in Network. Back restores the investigation.
4. Open **All network connections**, then **Interesting Traffic**, to inspect validated legacy Meterpreter TCP configurations. These belong to Network, including configurations saved in older download reports. **All findings** clears download column filters.

The report never assigns an unowned socket or global memory string to a process by proximity. A matching filename can refer to a different file. A configured reverse connection endpoint does not establish a successful connection or identify which executable owned it. Those gaps remain visible. Findings support bookmarks, case persistence and CSV export.

Residual process recovery currently supports the Windows x64 EPROCESS 19041 layout. It activates only after at least five timestamped inventory PIDs corroborate that layout. It scans downloaded names up to 15 bytes and bounds additional raw name searches to 128. Carved copies can survive after exit and do not prove that a process was active at acquisition. Other layouts and longer names rely on collected engine inventories. Download recovery retains at most 2,000 residual process candidates. Payload configuration recovery runs separately through Network. The report retains at most 10,000 findings plus coverage. Partial cached databases, missing sources and limits appear in coverage and Run details.

Select a memory image in the sidebar before using these tools. Results belong to
that evidence capture. Application analyses appear in the same queue and case
history as Volatility jobs, and their findings support bookmarks and CSV export.

## File and document recovery

Choose **File and document recovery** in New analysis to prepare file contents
before browsing. It collects missing FileScan and available Process handles
inventories, then attempts each distinct file object. Existing completed attempts
are reused. Each extraction keeps its own queue entry and diagnostics, so a large
capture can take time to process. FileScan, Dump files and Process handles are
basic analyses.

The report retains the source run and row, extraction run and recovery status.
Open recovered contents with the Sidebar to inspect hex, decoded text or SQLite
tables, or use Save as to export a cache variant. Recovery can produce partial
contents and does not guarantee that a document is complete.

**Show unavailable files** in the Files and Processes tree headers includes failed,
uncached and unsupported Windows file objects. It is enabled by default so failed
recovery or antivirus quarantine does not conceal file observations.
Untested files stay visible until an extraction establishes their status.
Directory pseudo-files such as `$Directory` and `$I30` directory-index streams
are always omitted from these trees. Original records remain in the case.

File recovery also searches the evidence bytes for absolute Windows executable
paths in UTF-8, UTF-16LE and UTF-16BE, retaining up to 10,000 distinct paths.
These rows say **Path reference only** and record the evidence byte offset.
They can reveal names whose file objects no longer survive, but do not establish
that the file was present, recoverable, or malicious. They cannot be passed to
DumpFiles as file-object addresses.

When an extracted file disappears before archiving or Windows reports a malware
block, the output name remains recorded as unavailable. Other outputs and parsed
findings are retained. VolGUI does not restore quarantined files.

Use **Retry extraction** in record details to retry a selected file. For older
captures whose unlabelled FileScan offsets are physical, pass `--physical` to the
recovery analysis or switch the selected file's offset button. Explicit virtual
and physical address columns take precedence. Status is matched by evidence,
address space and file-object address, rather than by path.

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

## Application memory

Enter a PID in **Application memory** and click **Scan process memory**. To choose
from the process inventory, click **Choose from Processes**, select a process and
click **Scan memory for PID**. In **New analysis**, the basic **Application memory
recovery and analysis** choice exposes PID and optional text-filter fields directly.
A PID is required; there is no application-name default.

VolGUI automatically queues unfiltered PsList and CmdLine when needed. After they
finish, it queues per-PID VadInfo and Memmap dumps, then the native text analysis.
These engine plugins are already basic choices. The installed engine must supply
all four plugins. Completed dumps are reused; exact inventory and dump run IDs
are saved with the parser job. Each extraction retains its own case history.

The memory reader continuously scrolls through the dump, loading only visible
byte blocks. Its fixed header labels ten-digit addresses, sixteen hex columns
and UTF-8 byte cells. Drag in either byte column, Shift-click, or use Shift with
arrow keys to select a range. The right sidebar decodes that range as UTF-8,
UTF-16LE or UTF-16BE and shows numeric values in both byte orders. Text decoding
starts at the first selected byte, including odd offsets. Decode and copy are
limited to the first 64 KiB of large selections. Ctrl+C copies hex or UTF-8 text
according to the column where selection began. Go to offset accepts decimal and
0x hexadecimal offsets. Ctrl+Home and Ctrl+End navigate to the dump boundaries.
The **Sidebar** toggle hides the decoder while preserving hex selection and scroll.
The entire dump is accessible, including bytes that produced no recovered strings.
Dump offsets refer to the logical process-dump file, rather than the acquisition file. Packed pages need not
be contiguous in virtual memory.

Search for a name, phrase or flag, then use **Previous match** and **Next match**
to move through recovered fragments and their original bytes. The full recovered
fragment appears below the selection decoder, preserving text spanning several pages.
Old or deleted copies remain separate fragments. **Bookmark fragment** and CSV
export use the existing case tools. A failed search leaves the dump readable.

CLI options support `--pid 5700` and `--contains "customer"` to filter by a literal
substring with ASCII case ignored. Every application uses the same text-carving
rules; no application document format is assumed.

The parser scans private writable user mappings and excludes mapped images,
read-only regions, shared pages and kernel addresses. Only contiguous mapped
ranges are joined. It carves UTF-8, UTF-16LE and UTF-16BE strings, including odd
offsets. Windows UTF-16 strings can also have a shifted interpretation in the
opposite byte order. Matching interpretations at adjacent byte offsets share one
candidate, with the other encoding and offset retained under Alternate interpretation.
Little-endian is the primary display convention on Windows. This does not prove
the original encoding; genuinely big-endian text retains its byte span in details.
Text must contain at least eight characters, four ASCII letters or digits, and
at least half ASCII characters. Text entirely in other scripts may be omitted.

These are text candidates. They may include old edits, undo data, resource text,
copied buffers or only part of a document. Nearby paths and process command lines
do not establish which file or tab owns a string. The parser does not reconstruct
Notepad's live tab objects, gap buffers or save state. It keeps competing versions
separate and labels document association and save state as unknown.
This distinction follows Microsoft's documentation that
[RichEdit does not store text as a simple character array](https://learn.microsoft.com/en-us/windows/win32/controls/em-gethandle).

Recovery is limited to 64 processes, 50,000 distinct candidates and 32 MiB of
retained text per analysis. Each fragment holds at most 64 KiB plus one Unicode
character; longer strings are split and marked as partial. Exact repeated strings
within a process and encoding share one row with an occurrence count and the first
source address. Mapping boundaries and limits remain in the finding details.
Missing, damaged or blocked artifacts appear in Run details. Use PID and substring
filters to narrow recovery if a result limit is reached.

## Process handles

Select a process and open its **Handles** details tab. This lists all collected
object types for its PID, 100 per page. **Collect handles for this process** queues
a PID-scoped Volatility job. Click a handle to see its full fields. File handles
retain the normal extraction actions. Non-file handles do not enter the file tree.

## File contents

Select a file and enable **Sidebar** in the bottom bar. Use the extraction action
when its bytes have not been recovered. The pane offers:

- Virtualized hex bytes, ten-digit offsets and UTF-8 byte cells.
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


## Network investigation

Network offers **Graph** and **Table** views. Graph shows IP nodes with clickable local and remote port labels. Table uses virtualized rows, sortable columns and horizontal scrolling for large result sets. Both views share search, protocol/state filters and two independent noise toggles. **Hide common system processes** uses a process-name list, including System and svchost.exe. **Hide local / empty endpoints** hides loopback, wildcard or unspecified endpoints, port 0 and records without remote endpoints. Both toggles start enabled. Turn either off to include those records. Private network addresses, missing owners and unknown ports remain visible. Noise toggles never hide analysis findings; search and protocol/state filters still apply to them.

Choose a focus IP or **All source IPs** from the IP dropdown. The canvas scrolls continuously through every peer, with controls created around the visible area. The IP picker has fixed widths for IPv4 and IPv6, highlights the current address, and stops Previous/Next at the first and last addresses. Click a port to list matching network entries in the endpoint sidebar. Click an IP for all its ports. The sidebar follows the same filters and retains repeated source runs. Credentials and payload configuration candidates appear first. Process buttons open the process view; clicking a card or table row opens its original record in the bottom details. Source bytes shows acquisition evidence at its saved offset. Back restores the view, noise filters and graph selection.

Run **New analysis > Network investigation and correlation**, or **Analyze network** in Network. This queues available Windows NetScan, NetStat, PsList, CmdLine, CmdScan, Consoles and Handles plugins, then correlates their collected records. CmdScan is a basic analysis choice. Completed unfiltered inventories are reused. Unavailable or failed inventories are listed in parser diagnostics.

Preprocessing reads IP-based SMB references, explicit net use credentials, TCP transport URLs and reverse-shell command candidates only from collected engine records. Each finding retains its source run, row and field. Credentials must appear in an explicit network drive command associated with that share. It also scans acquisition bytes for legacy Meterpreter TCP configurations, validating the session, URL padding, exit function, UUID and timeouts before reporting an endpoint. This scan retains at most 2,000 configurations and records acquisition offsets and evidence fingerprints. It does not search raw memory for credentials or arbitrary connection strings. Use Global string search or Process Memory for general text searches. Recovered command text can be stale or unexecuted and does not establish a live connection.

Select **Interesting Traffic** to filter recovered findings, SMB and common remote administration connections such as SSH, RDP and WinRM. If no completed current network parser exists, the button queues native recovery against saved inventories and the acquisition. Queued or running jobs are reused. New findings refresh the open Network view automatically. This recovery does not require another engine collection pass. Historical configurations from download reports appear in the evidence-wide Network view with their original source run, row and offsets. Saved records remain unchanged. New runs use parser version network-v3-configurations.

Recovered plaintext credentials are saved with the case and included in exports of those findings.
