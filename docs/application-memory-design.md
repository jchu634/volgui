# Application memory recovery

## Usage

Choose **Application memory recovery and analysis** in New analysis. A PID is
required and is entered directly in the workspace or analysis chooser; `--contains`
narrows text. The caller uses the same analysis draft, queue and native execution APIs as
browser analysis. Results use the existing case records, source bytes and exports. The workspace
uses synchronized hex and text panels with fragment navigation instead of a table.

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

## Design comparison

A process-scoped parser was chosen over a temporary corpus database of strings,
pointers and structures. Both can hide memory mapping details, but a corpus would
introduce a fact schema and query interface before a second application needs it.
The current parser can be extended with recognized editor structures later.

Whole-acquisition string searching was also considered. It cannot establish
process ownership or exclude unrelated kernel and shared bytes. DumpFiles alone
recovers cached file pages and cannot supply edits that exist only in an editor.

The design accepts repeated scanning when a user changes a filter in exchange
for a small interface and no second persistent index. It keeps carved candidates
and competing copies rather than inferring current document contents from string
length or proximity. No version-specific Notepad layout is assumed.

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
