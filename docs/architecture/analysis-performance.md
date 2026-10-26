# Analysis performance investigation

Measured locally on 26 October 2026 with the installed vol-rs 1.0.2 engine, a
4.57 GB Windows acquisition and `windows.memmap.Memmap --pid 5700 --dump`.
Sizes below are decimal. This investigation reads the existing case and tests
imports in temporary cases on the capture's volume.

## Where the time goes

The [analysis worker](../../src/ui/analysis_actions.rs) runs these steps in order:

1. Wait for the queued run's metadata to become durable.
2. Launch the CLI, sending stdout and stderr directly to files.
3. Parse `stdout.json` into a table after the CLI exits.
4. Archive outputs in the case object store.
5. Import observations into SQLite, then report completion and refill the slot.

Dump bytes do not travel through the GUI event channel. Archiving happens on a
worker, but the worker still occupies a job slot. All output publishers for a case
share `objects/.writer.lock`. The lock covers hashing, compression, chunk lookup,
pack appends and catalog publication. Database writers also serialize. Increasing
the simultaneous-job limit cannot make these sections run concurrently.

The installed CLI completed this dump in **2.28 seconds**, producing a
1,036,042,240-byte dump and 21,982,792 bytes of JSON with 125,604 mapping rows.
The existing case recorded 64 seconds for that run's full lifecycle. That history
includes queue and case conditions which the isolated benchmark does not recreate.

## Development build fix

The default build optimized SHA-256 and byte searches, but left the application,
LZ4 and bundled SQLite at development settings. LZ4's generic compression code
also instantiates in its caller, so optimizing only the dependency leaves a large
part of the cost in VolGUI.

[Cargo.toml](../../Cargo.toml) now optimizes VolGUI at level 2, and LZ4 and bundled
SQLite at level 3 in development builds. Debug assertions and debug information
remain enabled. GPUI dependencies retain their existing build settings. Release
settings and the case format are unchanged.

The same raw outputs were imported into fresh cases, one worker at a time, with
warm filesystem caches. The baseline has two runs and the updated build has three.
Table values are the median of each stage, rounded to two decimal places.

| Stage | Previous development build | Updated development build |
| --- | ---: | ---: |
| JSON loading | 1.75 s | 0.41 s |
| Output archiving | 20.79 s | 3.15 s |
| SQLite import | 6.62 s | 4.13 s |
| Total measured processing | 29.16 s | 7.71 s |

The median of the actual per-run totals fell from **29.16 s to 7.71 s**, about
**3.8 times faster**, or **74% less processing time**. This excludes CLI execution,
capture copying, metadata checkpoints and the verification pass. It is a
development-build result, not a measured improvement over a release build.

LZ4 optimization alone reduced archiving to 15.03 s. Optimizing the caller was
needed for the larger improvement. Three imports into a shared temporary case
also passed, exercising chunk reuse and observation deduplication. All updated
runs authenticated every archived chunk and complete output, compared output
digests and lengths with the untouched captures, and retained 125,604 input rows.
The final fresh-case and repeated-import checks also compared every stored row's
fields, hierarchy and order with the input table.

Validation passed with `cargo fmt --all --check`, all-target Clippy with warnings
denied, the full non-desktop test suite with `test-engine`, and the Windows
accessibility teardown regression. The standard suite leaves its three optional
external-data and synthetic-benchmark tests ignored.

## Repeating the benchmark

First capture the CLI outputs in a separate directory. Use the same engine,
evidence, symbols, cache, plugin and arguments as the source run. Do not use a
directory containing unrelated files. Then run:

```powershell
cargo run --locked --example benchmark_import -- <source-case-directory> <source-run-id> <raw-capture-directory>
```

The example reads source metadata, copies the raw outputs into a temporary case,
times JSON loading, archiving and observation import separately, then verifies
the archived outputs. It prints one JSON measurement per import and removes the
temporary case on exit. It does not write the source case or rehash the
acquisition. Copying and verification are outside the stage timings.

Pass a positive repeat count after the capture directory to measure later imports
against the same temporary chunk catalog and observation store. For independent
fresh-case samples, invoke the example separately for each sample. Avoid building
or running other analysis benchmarks during measurements.

Restart with a rebuilt application to use the new development settings. A running
executable keeps its original code. For normal use, `cargo build --release` also
optimizes the application and its dependencies.

## User-memory collection

Browser and application recovery now request `--user-memory` when the selected
vol-rs engine advertises it in Memmap's help. Of this dump's 1,036,042,240 bytes,
only **81,903,616 bytes** and
19,884 rows have virtual addresses below the x64 user boundary. The other
**954,138,624 bytes, or 92.1%**, are kernel mappings. Both browser and application
recovery discard these kernel ranges before scanning. Scoped collection avoids
writing, hashing and cataloging them in the first place.

In `D:\Repos\vol-rs`, `src/framework/plugins/windows/memmap.rs` implements the
opt-in scope. Full Memmap output remains the default. Scoped rows add an explicit
`User address limit`, and run arguments retain `--user-memory` as collection
provenance. This handles x64 processes with no mappings above 4 GiB and 32-bit
Windows `/3GB` splits without inferring width from kernel mappings.

Both complete full dumps and user-only dumps can satisfy these readers. Reuse
requires the same evidence and PID, a known complete argument set, and an available
dump. User-only dumps never replace a full manual Memmap request. Older engines
continue to use full dumps. Scoped results missing consistent boundary metadata
are rejected by the parsers. Already queued jobs keep their original arguments.

Build the updated CLI with `cargo build --release --locked` in `D:\Repos\vol-rs`,
select `D:\Repos\vol-rs\target\release\vol-rs.exe` in VolGUI Settings, then
validate and save. A rebuilt GUI probes support again when validating the engine.
The 92.1% byte reduction does not imply the same reduction in total runtime.

The rebuilt release CLI produced the same full JSON and dump bytes as the
installed engine. Every scoped mapping, compact file offset and user-space byte
was compared with the full dump. A warm comparison took 2.18 s for the full dump
and 0.33 s for the user dump. The first invocation of the freshly built executable
took 21.97 s; the warm numbers exclude that startup outlier.

One isolated import of the scoped outputs took 0.075 s to load JSON, 0.307 s to
archive and 0.436 s to import observations, totaling 0.82 s. It verified every
stored row and archived byte. These are single scoped-run measurements, compared
with the earlier three-run full-import median above. End-to-end Notepad recovery
through actual engine discovery, automatic job preparation, CLI execution,
archiving and parsing completed with 5,063 text candidates from the scoped dump.
A browser recovery run using the same capability detection and automatic scoped
collection returned 475 findings from one browser process. Both validation cases
are separate from the source case.

## Next improvements

The CLI also translates each region again in `write_region` after discovering its
mapping, and `IntelLayer::get_valid_table` clones cached page-table buffers on
translation. Streaming mapped reads and sharing immutable table buffers are
possible CLI optimizations. The measured CLI cost is small compared with the old
GUI processing cost, so these were left unchanged.

After the build fix, observation import is the largest measured stage. Each new
mapping row still performs observation lookup, entity insertion, observation
insertion, membership insertion and occurrence insertion. Memmap already skips
field-fact and full-text expansion. A specialized bulk mapping import could reduce
the remaining work, but would need to preserve immutable observations, deduplication,
row provenance, cancellation and atomic publication.

Moving chunk preparation outside the pack lock could reduce multi-job contention.
It would need a bounded staging queue and a recheck of chunk identities while
publishing. Measure a representative concurrent batch before choosing this change;
the single-worker numbers do not establish the best job limit.
