# Investigation workspace

## Problem

The starting application is a GPUI window with sample evidence and placeholder commands. The reference at localhost:5173 establishes the evidence sidebar, artifact detail, listing and job-status layout. The actual analysis engine is a separately installed executable. Its installation directory must retain its supporting DLLs, plugins and symbols.

## Usage

An investigator creates a case directory, adds memory images, and selects a discovered Volatility plugin. Evidence is referenced by absolute path and fingerprinted with SHA-256. Analyses run in background workers and save their command, engine version, timestamps, exit status, stdout and stderr. Selecting a completed analysis opens its records. Investigators can filter, sort, inspect, bookmark and annotate those records, then export a CSV or case report.

```rust,ignore
let mut case = Case::create(directory, name)?;
let evidence = Evidence::inspect(image_path, cancel, progress)?;
case.add_evidence(evidence)?;
let installation = Installation::discover(settings, cancel)?;
let run = installation.prepare(&evidence, plugin, arguments, &case.directory.join("analyses"))?;
case.queue(run.clone())?;
let outcome = installation.execute(&run, &case.run_dir(&run.id), cancel)?;
case.finish(&run.id, &outcome)?;
let store = ResultStore::at(&case.directory);
let index = store.query(&Query { runs: vec![run.id], ..Default::default() })?;
let visible = store.fetch(&index.ids[..index.ids.len().min(128)])?;
```

## Shape

- `case.rs` owns case validation, evidence fingerprints, durable manifests, run history, bookmarks, annotations, exports and recovery of interrupted jobs. Cases contain an ordered run history; each run has its own output directory. Original images are opened read-only.
- `volatility.rs` owns the external command protocol, plugin discovery, argument tokenization, process cancellation and JSON-tree conversion. Commands use an argument vector without a shell. Output streams go directly to separate files so progress cannot fill a pipe and stall a child.
- `results.rs` owns the SQLite schema, transactional imports, FTS substring index, numeric sorting, lightweight result IDs, visible-record batches and process hierarchy projection. Connections are short-lived and use WAL with a busy timeout. Existing completed output is imported once on case opening.
- `artifacts.rs` classifies related plugins into investigator-facing groups and defines evidence OS filters. Several scans can populate one shortcut. Empty groups stay visible and disabled.
- `analyses.rs` defines Basic analysis labels, catalog ordering/filtering, and per-evidence selections with separate plugin arguments. The chooser validates every draft before `Case::queue_batch` writes one manifest update. Import and New analysis share the same dialog. Cancelling it leaves imported evidence available without starting scans.
- `ui.rs` owns GPUI state and the reference-inspired workspace. Background threads return events through a channel. Only the UI mutates the active case. Case switching is disabled during background work. A serial analysis queue limits memory pressure and permits cancellation. `ui/artifacts_view.rs` renders the virtual results table and resizable details pane; `ui/popups.rs` owns reactive queue and artifact pickers; `ui/navigation.rs` restores a bounded history of pages, scopes and selections. Parent/child links query indexed PID/PPID projections on workers. Closing a case invalidates pending responses before releasing its writer lock.
- `settings.rs` owns per-user installation configuration and recent case locations. An installer or launch argument can supply the engine path. No engine executable or Python module enters the application package.

`Record` retains its original fields and tree depth. Bookmark identity is a run UUID plus the original flattened row index, unaffected by table filtering or sorting. Each rerun gets a new UUID and directory. Queued/running jobs found when reopening a case become interrupted instead of silently restarting.

## Alternatives considered

1. Embed a local web server and rebuild the mockup as a web frontend. This can reproduce the reference closely, but adds server lifecycle, IPC, two application runtimes and a second build system to a native Rust foundation.
2. Keep GPUI and extract a Rust investigation core. This hides CLI and persistence details behind a small domain API while allowing the existing application to grow. This is the chosen shape. The browser mockup remains a visual reference.

## Tradeoffs

- Keep case metadata in an atomic JSON manifest and completed records in SQLite. Raw JSON remains an audit artifact. UI searches and sorts run on workers; only visible row fields enter a bounded cache. Search text is debounced and stale worker responses are ignored.
- Run analyses serially to avoid several plugins loading a large memory image simultaneously.
- Show actual plugin output and field names instead of assigning unverified threat scores or inventing artifacts unavailable in the installed engine.
- Keep evidence at its original location. Moving a case does not copy large or sensitive images.

## Verification

Integration tests cover tree parsing, literal argument handling, case persistence, evidence change detection, interrupted-run recovery, CSV escaping and subprocess failure/cancellation. An opt-in test invokes the external build with `frameworkinfo.FrameworkInfo`, requiring no memory image. Manual validation also exercised `banners.Banners` and `windows.info.Info` on a 4.26 GiB VirtualBox capture with the installed symbols.
