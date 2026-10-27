# Partial matches

`Settings::show_partial_matches` is a global display preference, defaulting to
false for new and existing settings. View > Show partial matches and the Settings
checkbox persist it immediately. It does not change external engine options.

Producers opt in per record with `Partial match: true`, `Partial match kind`, and
`Validation failures`. The UI never guesses partial status from a finding's name
or from a run's Warning status. Producers include residual process recovery in
Download investigation, Process Memory, Browser activity, executable path
discovery and Beacon configuration recovery in both Network jobs. Quarantined
threats, literal string search, registry and external engine parsers are unchanged.

## Process recovery

The scanner reads acquisition chunks with overlap, searches for exact image names,
and subtracts the supported EPROCESS image-name offset. Eight-byte fields are
decoded as little-endian integers. PID, parent PID, creation and exit times and the
terminated image name must remain plausible. An intact candidate also requires
the expected process header, page-aligned directory-table base and dispatcher
links.

A damaged candidate can fail those leading-field checks only when both surviving
active-process pointers are aligned kernel addresses. Failed checks, parsed values
and acquisition offsets are retained. This is a bounded heuristic, not validation
of the linked records or proof of execution. Both classes require a layout
corroborated by at least five intact inventory identities; partial candidates
cannot corroborate a layout. Partial and intact candidates have separate limits,
and intact copies take precedence for the same identity.

Partial candidates are collected regardless of display preference so toggling
visibility does not require another scan. Older saved reports must be rerun once.
The unresolved download origin remains present when only a partial process matches.
Partial PIDs never receive socket joins, command-line enrichment, process identity
merges, inherited parents or file handles.

## Presentation and persistence

Each parser keeps its strict checks and uses a separate fallback for partial
records. `analysis::partial::mark` writes the common metadata;
`analysis::partial::bound` provides independent row budgets for mixed reports.
Partial overflow does not stop strict recovery or consume its row budget. Coverage
warnings report saturated budgets. Explicit user filters, process identity and
mapping bounds still apply. Existing visible incomplete Meterpreter configurations
and truncated browser URLs remain visible under their original semantics.

### Process Memory

Strict text still requires eight characters, four ASCII letters or digits and at
least half ASCII characters. The fallback accepts six or seven ASCII letters with
at least four distinct letters, a vowel and consistent lower/upper/title case, or
text with at least twelve characters, 75% letters, four distinct letters and two
words of at least three letters each. This keeps some non-ASCII multiword text
without admitting arbitrary printable heap words or shifted UTF-16 runs.
Candidates with eight to eleven characters must pass the strict checks; this
length band has no fallback. Common words and API-name fragments can still pass
the short-word gate, so partial text should be treated as leads that may be junk.

Partial fragments are at most 4096 UTF-8 bytes. The report retains at most 2000
partial rows and 2 MiB of partial text, independently of the existing 50000-row /
32 MiB strict limits. Both classes deduplicate exact strings and coalesce adjacent
shifted UTF-16 interpretations. Only validated private writable user ranges are
scanned. `--contains` applies to both classes.

### Browser activity

Memory recovery additionally retains delimited HTTP(S) URLs with single-label
intranet hosts. Hosts must contain at least two ASCII letters, be 3 to 63 characters
long, contain only letters/digits/hyphens with no leading/trailing hyphen, and have
a nonempty path beyond `/`. Credentials, incomplete intranet strings and bare
scheme/hostname markers are rejected. Partial URLs do not generate search terms
or query-parameter interpretations. There are at most 1000 partial URLs per PID,
independent of the 10000 strict URL limit.

Recognized Firefox and Chromium saved-session formats can retain HTTP(S)
navigation entries when the selected entry or Chromium window association is
missing. Known closed tabs/windows remain excluded. These are navigation
candidates, not visits, selected tabs or searches. The fallback inspects at most
32 entries per tab and keeps at most 2000 partial rows per profile; URL and title
lengths are each limited to 4096 bytes. Browser reports have independent limits of
100000 strict and 5000 partial rows. Profile-cache versions include this parser
change. Download investigation excludes partial Browser observations, including
directly reused profile results, from origin/executable-URL correlation.

### Executable paths

Strict drive-qualified paths remain unchanged. Partial references require UNC,
device/root-relative or relative directory context plus a complete `.exe`
basename with at least three distinct ASCII letters. Bare filenames, repeated or
invalid separators, invalid Windows characters, control/replacement characters,
overlong components and `.exe.config` suffixes are rejected. Partial paths are
limited to 2048 UTF-8 bytes and 1000 unique records, separately from 10000 strict
paths. UTF-8, UTF-16LE and UTF-16BE offsets identify the retained bytes and encoding.
ASCII UTF-16 can have an indistinguishable shifted opposite-endian interpretation.
Both standalone discovery and bulk Files recovery use this scanner. These remain
path references with unverified roots and no file-presence or ownership claim.

### Network configurations

Both acquisition and virtual-memory recovery share the Beacon fallback. It needs
coherent typed protocol, port, sleep, maximum-response-size and jitter settings,
valid host/URI pairs, and either a structurally valid RSA public key or both valid
HTTP user-agent and submit-URI strings. A marker or numeric prefix alone is
insufficient. Duplicate settings and invalid required numeric/endpoint fields are
rejected. Missing/invalid corroborating settings and damaged/truncated tails are
retained as validation failures when enough other anchors survive.

Partial configurations have `Candidate bytes SHA-256`, not the validated
`Configuration bytes SHA-256`. Provenance records acquisition coordinates or the
pinned process dump, PID, VAD and virtual/dump coordinates. Process memory proves
the presence of these candidate bytes, not payload identity, execution or a
successful connection. Existing raw endpoint and incomplete Meterpreter findings
retain their previous classification.

Each scan window retains at most 200 partial endpoint records. Acquisition
recovery retains 500 partial endpoints per report; process attribution retains
1000. The existing strict limits, byte coverage and discovery scope remain in
force. Parser versions invalidate automatic reuse of older Network reports.

### Validation limits

Synthetic tests cover rejected noise, truncated/malformed fields, source bytes,
closed session state, independent limits, visibility after reopening and partial
Browser records staying out of Download correlation. Flood fixtures place partial
candidates before later strict findings. These checks establish bounded behavior,
not precision or recall on an arbitrary real capture. Newly recovered partial
classes require rerunning older reports once; toggling visibility then needs no
further scan.

## Display

General queries and hierarchy queries exclude partial records unless explicitly
requested. Raw run tables remain complete. CSV exports using a filtered query
respect that query's preference and retain partial metadata when included.

Tables, tree rows, network occurrences and nodes containing partial observations
use muted amber with dark text. Table rows paint a continuous background behind
cell padding. The title bar shows the global mode beside the case name. Details
use a compact Partial Match badge beside the bold item name, with failed checks
and interpretation limits in its tooltip. Network nodes mean "contains partial matches" and may also represent
intact entries. No existing incomplete network finding is reclassified.

The Processes tree projects partial process findings from download reports for the
same evidence as isolated roots. Their provenance continues to identify the
original report row. A tentative PID cannot attach itself to the validated
hierarchy or assign file ownership. Original source cases are never rewritten by
this projection.
