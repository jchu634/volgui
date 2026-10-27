# Job optimizations and coverage warnings

This implements the changes investigated in
[the profiling report](job-profile-2026-10-27.md).

## Completion policy

`RunStatus::Warning` is a terminal state for incomplete coverage that requires
different inputs, scope or limits. It retains available findings, row counts,
exports, annotations and diagnostics. It is saved in the existing run status
column, so no case-format migration is required.

Native producers attach coverage diagnostics to `Table::warnings`. The worker
uses this structured metadata to choose Warning, puts the first reason at the
start of the run message, and archives that message with the output. Finding rows
and their export columns stay separate from completion metadata. Reloaded results
use the persisted run status and message.

Publication also checks output availability metadata. Parsed findings remain
available when extraction outputs are blocked or archiving is incomplete, and
the job receives Warning rather than Completed. Cancellation and failed result
imports retain their own terminal states.

Limits, skipped invalid ranges, unavailable artifacts, damaged profile data and
missing required inventories now produce warnings. A supported analysis scope,
such as scanning readable user memory or reading standalone SQLite pages, is
still described in the result. An ordinary transient execution failure remains
Failed. Cancellation remains Cancelled.

Warning results appear in the queue and history, and remain selectable. They
require an override in the analysis chooser and are excluded from ordinary retry
and the completed/failed queue-clear actions. Run details retain all reasons;
the user can configure a narrower analysis after reviewing them.

When an older case is opened, a completed Network attribution result that
explicitly recorded the old byte/finding-limit stop is promoted to Warning. Its
findings and original diagnostic remain intact. This compatibility correction
uses the older saved message; new executions use structured metadata.

## Changes

- Imports reconcile process associations only when they insert new observations
  with a process identity role. Empty imports, identical observations, VADs,
  memory maps and unrelated findings skip the rebuild. Identity changes still
  rebuild associations in the same cancellable transaction, preserving PID-reuse
  ambiguity and provenance.
- Short Netcat discovery markers require printable command context containing a
  numeric port, including UTF-16 commands. Beacon discovery requires its protocol
  setting and another coherent typed header. These checks select candidates;
  the final parsers still validate findings. Longer program markers and partial
  structured prefixes retain labelled fallback coverage. Shared, image and
  read-only VAD scope is preserved.
- Regex dependencies use optimization level 3 in development builds.
- Browser and Download share artifact classification and profile parsing by
  immutable SHA-256, parser version and fallback mode. The process cache allows
  4,096 entries and 32 MiB of serialized row payload. Failed and bounded parses
  are not cached. Provenance and file-owner attribution are assigned for each
  source after parsing. A reusable catalog connection avoids repeated connection
  setup. Availability checks remain live, including on cache hits.
- Browser distinguishes known unrelated process dumps from missing browser
  identities. Dumps collected by Network do not themselves imply incomplete
  Browser coverage.
- Recovery barriers apply to their own evidence. Independent evidence can use
  free job slots while a recovery parser waits or runs. Prerequisite order and
  the configured concurrency bound still apply. Publication continues to use
  the existing atomic pack writer lock.
- A per-process Network scan limit no longer stops later processes. The total
  4 GiB and finding limits still stop the job, with explicit coverage warnings.

## Measurements

Measurements replay the A4-A1 case without editing its catalog or acquisition.
The import benchmark copies the catalog; native benchmarks use isolated catalogs
and output references. Some measurements overlapped builds or other benchmarks,
so they do not establish a complete workflow wall time.

Three-sample populated-case import medians:

| Import | Earlier report | After change |
| --- | ---: | ---: |
| Empty | 4.183 s | 0.016 s |
| 97 VAD rows | 4.141 s | 0.031 s |
| 2,444 memory-map rows | 4.522 s | 0.104 s |

All 18 new fresh/populated import samples verified stored rows, order and
hierarchy. The current catalog may contain additional observations compared
with the original report.

Final Network discovery selected **4 PIDs instead of 195**, producing eight
observations. Both PIDs with previously confirmed findings, 4556 and 10416,
remained selected. The final discovery replay took **141.8 seconds**; discovery
itself did not become faster than the earlier 55-second run. The reduced fan-out
targets the much longer collection phase. Four candidates require at most eight
per-process collections; reuse determines how many new jobs are needed.

Attribution using those candidates reused the existing collections, scanned
**all four processes and 302,878,720 bytes**, and returned **six findings** in
**2.50 seconds** of analysis. It did not reach a scan limit. All six matched the
previous focused and broad findings on PID, finding type, program, endpoint,
virtual address, dump offset, byte length and configuration hashes. This restores
the five PID 10416 findings omitted by the earlier broad cutoff. It is a
comparison of different selected work, rather than a fixed-work parser speedup.

Two Browser treatment samples each returned 28,768 rows and the same output
hash. Parsing took 29.36 seconds cold and 15.87 seconds with cached profile work.
A replay with the saved baseline executable on the current case took 29.66 and
29.61 seconds. Both baseline samples also returned 28,768 rows. Diagnostic
wording can differ, so these are not claimed to be byte-identical across builds.

Raw evidence is under `target/verification/job-profile-2026-10-27/`:
`import-scaling-optimized.json`, `discovery-optimized-final.json`,
`network-attribution-optimized.json`, its findings JSON,
`finding-preservation.json`, `native-baseline-current.json` and
`native-optimized.json`.

## Reproduction

Build the three profiling examples with `CARGO_INCREMENTAL=0` if the local Windows
incremental linker issue recurs. Run executables directly after building:

```powershell
cargo build --locked --no-default-features --example profile_import_scaling --example profile_network_discovery --example profile_native_jobs
target/debug/examples/profile_import_scaling.exe <source-case> <imports.json> <vad-run-id> <memmap-run-id>
target/debug/examples/profile_network_discovery.exe <source-case> <discovery.json>
target/debug/examples/profile_native_jobs.exe <source-case> <native.json> <prepared-attribution-run.json> 1 ProcessAttribution <discovery.json>
```

The optional discovery argument imports the replay observations only into the
profiler's isolated catalog and prepares attribution through the production
planner. It refuses to continue if candidate collections are missing. The
discovery tool needs an existing discovery command for a comparable replay.

Regression coverage includes warning persistence and exports, old-result
promotion, retry exclusion, process/total/finding limits, exact budget completion,
cross-evidence scheduling, conditional reconciliation and rollback, supported
command/Beacon fixtures, shared profile parsing and newly blocked cached files.

Validation commands:

```powershell
cargo test --locked --no-default-features --lib --tests
cargo clippy --locked --all-targets -- -D warnings
```
