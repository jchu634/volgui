# Job profiling, 27 October 2026

The largest measured opportunities are avoiding unnecessary process-association
rebuilds during imports, making Network discovery selective, optimizing regex
dependencies in development builds, and reducing repeated recovered-file probing.
Increasing the concurrent job setting alone will not address these costs.

## Scope and method

Measurements use the A4-A1 case and its 4,573,052,780-byte Windows acquisition,
the configured release vol-rs executable, and VolGUI's optimized development
build. The machine has 32 logical processors and 64 GiB RAM. The desktop remained
open and continued its Network collection batch throughout the investigation.
These measurements therefore include machine contention and cache effects.
Separate benchmark cases avoid sharing the source case's SQLite writer lock.

Three samples were taken for each of nine native job types. Native analysis,
JSON writing, archiving and result import were timed separately. Progress-event
timestamps distinguish recovered-file processing from subsequent memory scanning.
Input backup, case creation, unbuffered comparison writing and verification are
outside the reported native totals. Each total is the median of the per-sample
totals, rather than the sum of stage medians.

All 27 native samples retained the same output hash within each job type. Each
sample compared buffered output with an unbuffered writer byte for byte and
compared stored row fields, hierarchy and order with the input.

Source catalogs were backed up through read-only SQLite connections under a
stable read transaction. Native input catalogs and filesystem references were
isolated; archived packs were hard-linked and only read. Import scaling copied
only the catalog and never accessed or published binary objects. The source case
and acquisition were not edited by the investigation.

Local raw measurements are in `target/verification/job-profile-2026-10-27/`:

- `native.json`: 27 stage measurements, progress timestamps and output hashes.
- `import-scaling.json`: 18 verified fresh/populated import comparisons.
- `engine-stages.json`: six engine runs and six verified fresh-case imports.
- `discovery.json`: saved discovery observations.
- `run-history.json` and `run-history-final.json`: two read-only history samples.
- `capture_engine.py`: the command replay used for engine timings.
- `run-history-completed.json`: completed broad attribution and collection history.
- `broad-attribution-run.json`: reconstructed pinned inputs for broad replay.
- `broad-attribution-completed-findings.json`: the completed job's stored finding.
- `broad-attribution-profile.json`: isolated broad replay with CPU timings.
- `broad-attribution-per-process.json`: intervals between PID progress events.
- `broad-attribution-regex-optimized.json`: the same broad request with optimized
  regex dependencies.
- `regex-build-experiment.json`: build overrides and comparison checks.

## Network collection fan-out

The current Network workflow has several distinct costs:

1. Collect missing process, socket, command and handle inventories.
2. Run native acquisition configuration scanning and record correlation.
3. Discover process candidates with `windows.vadregexscan.VadRegExScan`.
4. Reuse or collect each candidate's VadInfo and Memmap dump.
5. Run `volgui.network.ProcessAttribution`, archive its output and import findings.

The broad attribution request recorded **55 seconds** for discovery. Its
8,479 observations selected **195 of 199** process inventory rows' PIDs. Deferred
preparation added **192 VadInfo jobs and 154 Memmap jobs**, or 346 collections.
Existing compatible results already avoided 44 of the 390 possible collections.

| Discovery match family | Observations | Distinct PIDs |
| --- | ---: | ---: |
| Seven-byte unencoded Beacon header | 4,994 | 191 |
| Narrow `nc` followed by whitespace | 2,002 | 194 |
| UTF-16 `nc` followed by whitespace | 1,477 | 184 |
| Other markers | 6 | 2 |

PID sets overlap. 193 PIDs were selected exclusively through the short marker
families. These are candidates, not 193 proven false positives. In particular,
changing selection must retain actual Netcat commands and valid configurations.

The narrow pattern accepts `\s+`, including line breaks and form feeds. The wide
program patterns have no preceding word boundary. The Beacon discovery pattern
checks seven header bytes; the full parser subsequently validates much more of
the configuration. Selecting any matching PID therefore makes discovery almost
equivalent to collecting the entire process inventory on this capture.

The completed history now supplies the full workflow timing:

| Phase | Recorded interval, UTC | Elapsed |
| --- | --- | ---: |
| Discovery | 06:54:51 to 06:55:46 | 55 s |
| 346 collection jobs | 06:55:46 to 07:16:05 | 20 min 19 s |
| Final attribution job | 07:16:05 to 07:21:59 | 5 min 54 s |
| Entire request | 06:54:51 to 07:21:59 | **27 min 8 s** |

All 346 collections completed. Their median recorded run duration was 17 seconds
for both VadInfo and Memmap. The longest VadInfo took 41 seconds and the longest
Memmap took 37 seconds. These durations include checkpoint waits, engine
execution, parsing, archiving, import and contention. They are not CLI-only
timings, and overlapping job durations must not be summed as workflow wall time.
The final job timing similarly includes publication and import.

The final report contains **one finding**, from PID 4556. It scanned 167 processes
and exactly **4,294,967,296 bytes**, reaching the global byte limit. Completion
therefore does not mean that all selected processes were scanned. Candidates are
visited in ascending PID order. PID 10416 is candidate 180 of 195, beyond the
observed limit; the focused run's five findings from that process are absent
from the broad result. The 28 later candidate PIDs require separate coverage.

This strengthens the case for selective discovery: irrelevant candidates consume
both collection time and the parser's finite scan budget. Simply increasing the
byte budget would increase work and would not address candidate quality.

An isolated broad replay reproduced the original output byte for byte, including
its SHA-256 `520f726f64d1407ab9aabe52e3eb03b4447303005c69e54d011a24f17fa35a1d`,
input fingerprint, 167-process coverage and 4 GiB limit. Native analysis took
**221.196 seconds wall time and 219.719 seconds CPU time**. Fresh-case output
writing, archiving and import added approximately 0.029 seconds. This is one
sample under different cache and machine conditions from the desktop run; the
354-second desktop job and 221-second replay are not an optimization comparison.
The CPU-to-wall ratio establishes that this replay is primarily CPU-bound.

The most expensive PID intervals were 1920 at 8.05 seconds, 1436 at 7.67 seconds,
448 at 7.00 seconds and 1720 at 6.76 seconds. These intervals include each PID's
table loading, mapping work and scanning, rather than just regex execution.

The persisted deferred request retained empty arguments, so its pinned replay
arguments were reconstructed from preceding completed inventories, discovery and
compatible collections. The reconstructed input fingerprint matches the original
report exactly, and the complete output hash matches the archived original.

## Development regex optimization experiment

The application crate already uses optimization level 2 in development, but
`regex`, `regex-automata`, `regex-syntax` and `aho-corasick` retain Cargo's default
development optimization level 0. The program-marker scan uses these libraries
for every readable window, even when no valid command is found.

A second build used temporary Cargo overrides setting those four dependencies
to optimization level 3. Application logic, parser expressions, input collections
and scan limits were unchanged. One full broad sample per build gave:

| Broad native analysis | Current development settings | Optimized regex dependencies |
| --- | ---: | ---: |
| Wall time | 221.196 s | **31.948 s** |
| Process CPU time | 219.719 s | **31.547 s** |
| Findings | 1 | 1 |
| Processes scanned | 167 | 167 |
| Logical bytes scanned | 4,294,967,296 | 4,294,967,296 |

This was **6.92 times faster**, or **85.6% less native analysis time**, in this
single full comparison. PID visit order, completion message, output bytes and
SHA-256 were identical. Buffered/unbuffered output and imported rows also passed
the existing checks. CPU time fell with wall time, which supports an actual
computation improvement rather than attributing the difference only to caches.
Additional samples would be needed to characterize run-to-run variance.

A supporting marker-regex microbenchmark scanned the same 1,593,344-byte saved
dxdiag range 128 times, with zero matches in both builds. Time fell from 4.635
seconds to 0.080 seconds. This no-match microbenchmark isolates regex traversal;
its approximately 58-fold improvement is not the whole-parser speedup.

The experiment addresses the native parser stage in a development build. It does
not establish an improvement over a release build, shorten the 346 collection
jobs, or expand coverage past the byte limit. Cargo.toml remains unchanged; the
overrides were supplied only to the experimental build commands. An already
running desktop application retains its existing executable.

For comparison, replaying PID 10416's commands into fresh directories gave these
three-sample medians:

| Collection | CLI | JSON load | Archive | Fresh-case import |
| --- | ---: | ---: | ---: | ---: |
| VadInfo, 88 rows | 0.043 s | 0.016 s | 0.012 s | 0.012 s |
| User Memmap, 2,444 rows, 10.66 MB output | 0.138 s | 0.021 s | 0.065 s | 0.042 s |

Each replay used a new output directory. CLI JSON and dump hashes agreed across
the three runs. Archived contents, full output hashes and imported rows were
verified. One selected PID is not representative of every process, but it shows
why treating the recorded 16 seconds as engine CPU time would be misleading.

## Case size adds a repeated import cost

`ResultStore::insert_cancellable` unconditionally calls `identity::reconcile`
before committing. Reconciliation reads all process-related observations for the
evidence, removes derived relations, resets memberships and rebuilds associations.
Its relation deletion also selects all observations belonging to the evidence.
This runs even for an empty table or a mapping-only import with no new process
identity facts.

The isolated populated catalog contained **1,874,621 observations**, including
**75,135 process-related observations**. The same import API was exercised in a
fresh case and a populated copy. Three samples per cell gave:

| Imported input | Fresh case | Populated case |
| --- | ---: | ---: |
| Empty table | 0.007 s | **4.183 s** |
| 97-row VadInfo replay | 0.013 s | **4.141 s** |
| 2,444-row Memmap replay | 0.046 s | **4.522 s** |

The populated replays reuse existing immutable observations, while fresh cases
insert new observations. This is not a comparison of identical insertion work.
The empty-table control has no observation insertion in either case and confirms
that catalog-wide work alone costs seconds. Verification checked columns, row
fields, order and hierarchy in all 18 samples.

Imports hold the case's single SQLite write transaction during reconciliation.
Other imports, metadata checkpoints and output publication must wait for that
writer. The object-store publisher also holds `objects/.writer.lock` through
chunk preparation and publication. A job retains its configured slot until
archiving and import finish. More engine workers can therefore increase waiting
without increasing database throughput.

## Native job timings

Times are seconds. The attribution measurement in this table is the prepared
**PID 10416** request. The completed broad job is described above.

| Native job | Rows | Analysis | Write | Archive | Import | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Process Memory | 2,088 | 0.230 | 0.009 | 0.032 | 0.343 | 0.611 |
| Browser activity | 27,644 | 32.431 | 0.079 | 0.119 | 6.135 | **38.761** |
| Download investigation | 32 | 17.149 | 0.001 | 0.014 | 0.017 | **17.179** |
| File path references | 1,769 | 3.627 | 0.003 | 0.015 | 0.077 | 3.722 |
| File recovery report | 11,854 | 3.783 | 0.012 | 0.035 | 0.610 | 4.456 |
| Network investigation | 5 | 2.281 | 0.001 | 0.012 | 0.011 | 2.307 |
| Selected Network attribution | 5 | 0.511 | 0.001 | 0.013 | 0.011 | 0.536 |
| Quarantine investigation | 1 | 0.999 | 0.001 | 0.012 | 0.010 | 1.022 |
| String search | 10,000 | 0.689 | 0.008 | 0.032 | 0.563 | 1.297 |

File recovery measures its native reporting phase, excluding engine extraction
jobs. String search uses the saved request's options. Native import measurements
use fresh cases and therefore exclude the populated-case cost above.

Browser recovery probed **2,540 recovered files** but reported findings from
13 profile files. Its later two samples spent 19.26 and 19.35 seconds before
process-memory scanning began, then 13.02 and 13.08 seconds in memory processing
and finalization. The first sample was slower, at 79.78 seconds overall.
The memory phase processed 39 browser dumps.

Download investigation invokes browser profile recovery again. In its later two
samples, 14.60 and 15.14 seconds elapsed before the first raw acquisition-scan
progress event. Progress then covered the scan in approximately two seconds.
Profile processing, rather than raw scanning alone, is the first target here.

Browser parsing currently opens every recovered DumpFiles output to probe its
header, including DLL images and event logs. Opening an archived artifact also
performs repeated availability checks and catalog connections. Its per-file
owner matching searches candidate and run lists again. These are concrete code
paths to instrument further before choosing between batching and cached parsing.

## Recommended order of work

1. **Avoid unnecessary association rebuilds.** Track whether an import inserted
   process identity facts that can change associations. Skip reconciliation for
   empty, unchanged and unrelated imports. Then consider limiting rebuilds to
   affected PIDs. Preserve PID-reuse ambiguity, provenance, atomic publication
   and cancellation. The 4.18-second empty import is a measured removable-work
   target, not a measured implementation speedup. This is the first change to
   try because it applies to every workflow and can preserve collection coverage.
2. **Validate Network candidates before full collection.** Add bounded context
   and structured checks during engine discovery, or scan readable VADs with the
   final parser inside the engine. Collect only the supporting ranges needed for
   provenance. Preserve the current shared/image/read-only VAD scope; using only
   private writable memory would change coverage. Keep labelled fallback coverage
   for incomplete candidates. Check known Meterpreter, Beacon and command fixtures
   before accepting any narrower discovery expression. Dropping `nc` or Beacon
   markers outright is not a valid performance fix.
3. **Optimize regex dependencies in development builds.** The measured broad
   analysis comparison improved from 221.2 to 31.9 seconds with identical output.
   This is a small build-setting change to consider alongside import work. It
   does not substitute for selective discovery or restore omitted PID coverage.
4. **Share recovered-artifact classification and profile parsing.** Batch catalog
   lookups, reuse a reader context, pre-index file ownership and cache results by
   immutable output hash plus parser version. Browser and Download should reuse
   profile work while retaining their separate interpretations. Preserve blocked
   artifact diagnostics and unknown-source handling. The approximately 15 to 19
   seconds before memory scanning is the target; a cache speedup is not measured.
5. **Revisit scheduling after shortening imports.** Native recovery jobs currently
   act as global queue barriers, including Network and attribution. Explicit
   dependency tracking could allow independent jobs to overlap. Preparing chunks
   outside the pack lock could reduce publication contention. Both need bounded
   queues and a concurrent batch benchmark; neither should be justified by a
   single-worker timing or by increasing the job limit from its current five.

## Reproduction and validation

```powershell
cargo run --locked --no-default-features --example profile_native_jobs -- <source-case> <output-json> <prepared-attribution-run-json> 3
cargo run --locked --no-default-features --example profile_import_scaling -- <source-case> <output-json> <completed-vad-run-id> <completed-memmap-run-id>
cargo clippy --locked --no-default-features --example profile_native_jobs --example profile_import_scaling -- -D warnings
```

The broad replay uses `broad-attribution-run.json`, one repeat and the final filter
`ProcessAttribution`. The optimized build command was:

```powershell
cargo build --locked --no-default-features --example profile_native_jobs --config 'profile.dev.package.regex.opt-level=3' --config 'profile.dev.package.regex-automata.opt-level=3' --config 'profile.dev.package.regex-syntax.opt-level=3' --config 'profile.dev.package.aho-corasick.opt-level=3'
```

Run the resulting executable directly for the treatment. A subsequent ordinary
`cargo run` can rebuild it with the default profile, losing the overrides. The
native profiler records process CPU time on Windows and PID progress intervals
for attribution; CPU fields are null on other platforms.

The scaling example makes one isolated catalog copy, inserts an empty control and
replays each requested table into fresh cases and that copy. Every replay gets a
new run ID. Copying, metadata saves and verification are outside import timing.
Fresh cases start empty each time; the populated copy reuses observations.
Allow space for a full catalog copy on the source volume.

Both profiling examples built and passed Clippy with warnings denied. Formatting
and whitespace checks passed. No production scheduler or parser behavior changed.
The initial native profiler build hit an existing incremental-link failure;
rebuilding with `CARGO_INCREMENTAL=0` succeeded. Its first input backup was also
restarted repeatedly by live case writes. The profiler now holds one SQLite read
snapshot while backing up, and the subsequent complete run succeeded.

An interrupted initial profiler left
`C:\Users\Joshua\Documents\Volgui\.tmpvUlB2D`, containing only its temporary
input backup. Automatic approval review blocked cleanup of this directory.
Successful benchmark runs cleaned up their own temporary cases normally.
