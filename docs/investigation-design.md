# Investigation services

The investigator chooses Browser activity, Global string search, a process's Handles
tab, or Browse hive on a registry result. Findings use the same SQLite records,
bookmarks, exports and case history as engine output.

Two designs were considered. Separate, transient panels would make services easy
to add but lose export, provenance and reopening. Native analysis runs reuse the
case queue and store. The latter keeps one owner for results and cancellation.

`investigation::prepare(evidence, plugin, arguments) -> Run` creates an application
job. `execute(directory, document, run, cancel, progress) -> Outcome` performs work
on the existing worker thread. Only known application job IDs bypass Volatility.
Browser recovery queues targeted DumpFiles jobs first, then parses recovered
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
