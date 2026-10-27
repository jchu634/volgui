# Application memory recovery

## Usage

Start recovery for a chosen PID from Process Memory or a process action. The native
application analysis is excluded from both chooser modes. `--contains` narrows
recovered text. The caller uses the same analysis draft, queue and native execution
APIs as browser analysis. Results retain source bytes, records and exports.

## Source trace and shape

`AnalysisDraft::prepare_in_case` validates options and engine capabilities, queues
missing process inventories and adds a deferred native job. `next_queued_run`
treats recovery parsers as queue barriers. The desktop resolves a deferred job
through `prepare_application_recovery`, considering only preceding jobs.

`application::recovery_runs` selects processes from unfiltered PsList, adds command
line context, reuses or requests per-PID VadInfo and Memmap, and pins those exact
source IDs in the parser arguments. The deferred job retains its ID. Failed
prerequisites fail recovery; retries preserve user options and resolve new sources.

`application::analyze` validates source capture and completion, reads mapping
metadata from the case store, and scans verified process-dump artifacts. Shared
`process_memory::regions` validates lengths and user address limits while retaining
the mapping between virtual addresses and logical dump offsets. The application
parser intersects those ranges with private writable VADs before scanning text.

The scanner keeps fixed-size chunks and bounded UTF-8 and UTF-16 decoders. It
keeps text candidates under row, byte and fragment limits. Every row carries text,
encoding, PID, source IDs and a byte span. Native execution and case finishing
archive the findings and source artifacts through the existing object store.

## Design

Process-scoped parsing preserves ownership and excludes unrelated kernel/shared bytes. DumpFiles alone cannot recover edits held only in process memory. The parser keeps competing text copies without inferring current document contents or assuming an editor-specific layout.

## Limits and evidence

Notepad uses RichEdit, whose text is not a simple array. A readable copy cannot
prove active tab state or a file association. The initial parser therefore labels
both unknown. The scanner requires ASCII anchors to reject arbitrary heap words;
it can omit text entirely in other scripts. Shifted UTF-16 interpretations of the
same text at adjacent byte offsets share a candidate, with the alternate encoding
and address retained in details.

`examples/validate_application.rs` exercises the same queue expansion in a separate
case. Synthetic tests cover damaged encodings, gaps, provenance, persistence and
exports. A real capture must still be checked against its retained bytes before
treating a candidate as evidence of the requested text.

## Shared investigation services

The investigator chooses Browser activity, Global string search, a process's Handles
tab, or Browse hive on a registry result. Findings use the same SQLite records,
bookmarks, exports and case history as engine output.

`analysis::prepare(evidence, plugin, arguments) -> Run` creates an application
job. `execute(directory, document, run, cancel, progress) -> Outcome` performs work
on the existing worker thread. Only known application job IDs bypass Volatility.
Profile recovery queues targeted DumpFiles jobs first, then parses recovered
SQLite history and session files. It does not treat arbitrary URLs as open tabs.
Every finding retains the source extraction and file, plus original path when
available. Session tabs describe the recovered session snapshot, not a guarantee
that the browser was running at capture time. Cache variants remain distinguishable.

String search reads evidence in bounded chunks, searches UTF-8 and UTF-16 in both
byte orders, and records file offsets, encoding and context. Offsets are evidence
file offsets, not virtual addresses. A result limit is explicit in run diagnostics.

Registry browsing uses PrintKey with a hive offset and relative key path. It
loads immediate children on demand and can request an entire subtree. The raw
plugin table remains available, including value types and data. Handles are queried
by evidence and PID, without the file-only filter used by the file tree.

File content reads remain paged. Text decoding is explicit, and SQLite contents
are inspected using read-only queries. No recovered program is executed.

Format references:

- [Volatility PrintKey](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/registry/printkey.html)
- [Chromium session commands](https://chromium.googlesource.com/chromium/src/+/main/components/sessions/core/session_service_commands.cc)
- [Chromium navigation serialization](https://chromium.googlesource.com/chromium/src/+/main/components/sessions/core/serialized_navigation_entry.cc)
- [Chromium session storage](https://chromium.googlesource.com/chromium/src/+/main/components/sessions/core/command_storage_backend.cc)

Encrypted Chromium session formats are reported as unsupported. Missing pages,
WAL-only history, private browsing and evicted caches can limit recovery. Parser
warnings remain in the analysis diagnostics rather than becoming invented rows.

### Browser process memory

`browser_memory_runs(directory, document, evidence, engine, cancel)` selects
browser PIDs from the latest completed PsList and CmdLine for that evidence,
queues PID-scoped Memmap dumps, then the existing native browser Activity job.
`src/lib/analysis/browser/memory.rs` owns process identity, dump mappings, URL scanning and memory
finding provenance. `src/lib/analysis/browser/search.rs` owns provider host/path/parameter rules.
The UI only queues runs and displays stored records.

Map metadata is validated before reading. Bad ranges are skipped with diagnostics
while other readable ranges remain available. Adjacent virtual and dump ranges are
coalesced; gaps remain separate. User ranges use validated address limits from mapping metadata, with architecture-aware
fallbacks for full dumps. Masked kernel addresses are excluded. Shared
kernel mappings cannot establish browser attribution. URL buffers are bounded,
reads are cancellable, exact strings are grouped per PID and incomplete strings
never produce search terms. Each finding retains its representative dump offset,
virtual address, command line and source run. Memory search rows remain distinct
from history visits and saved session tabs. No timestamp is inferred. Known automated Edge annotation queries are labelled
separately; other query origins remain unknown. A byte delimiter does not prove
that adjacent ASCII text belongs to a semantically clean URL.

Profile attribution collects every matching Handles owner rather than accepting
the first FileScan match. Several owners remain Related PIDs, with no arbitrary
single PID presented as the process that performed a historical search.
