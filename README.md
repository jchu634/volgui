# VolGUI

A native Rust/GPUI investigation workspace for the external Volatility 3 CLI. Evidence and artifact navigation sit on the left, matching results fill the main table, a resizable details pane sits below it, and analysis status appears at the bottom.

## Run

Build with a current Rust toolchain and the Windows C++ build tools required by GPUI.

```powershell
cargo run --bin volgui -- --volatility D:\Repos\vol-windows-x64\vol.exe
```

The executable path can also be supplied by an installer using the `VOLGUI_VOLATILITY` environment variable, or selected in **Settings**. Validated settings persist in `%APPDATA%\VolGUI\settings.json`. `VOLGUI_CONFIG_DIR` overrides that directory for portable installations or testing. No development-specific engine path is compiled into the application.

Keep the external build's executable, DLLs, plugins and supporting files together. VolGUI neither bundles nor copies Volatility. Engine installation, distribution and licensing remain separate. Volatility's own CLI behavior is documented in its [official manual](https://volatility3.readthedocs.io/en/stable/vol-cli.html).

## Investigation workflow

1. Use the welcome-screen **New case**, **Open case**, or **Open recent case** buttons, or the titlebar **File** menu. **File > Settings** opens the installation dialog.
2. Use the **+** beside Evidence or **File > Add evidence** to import memory images. VolGUI opens them read-only and computes SHA-256 on a background thread. Hashing can be cancelled. The analysis chooser opens after import; **Choose later** keeps the evidence without starting scans.
3. In the chooser, select the evidence OS and check the analyses to run. Shift-click a checkbox to select or clear the range from the last checked analysis in the displayed order. Basic investigation tasks appear first. **Show advanced analyses** reveals the remaining discovered plugins, including common framework plugins. Search, range selection and select-all apply to visible rows. For a multi-file import, each evidence tab keeps its own OS and selections. **New analysis** opens the same chooser for the current evidence.
4. Use a row's **Options** button for plugin-specific arguments such as `--pid 3488`. Each analysis keeps separate arguments. Use quotes around values containing spaces. Commands use a literal argument vector without a shell. The GUI supplies `-q -r json`, the memory image, optional symbols/offline settings, and an output directory.
5. Confirm with **Queue N analyses**. The complete selection is validated and saved together before jobs start. The OS choice is saved with each evidence file. The statusbar dropdown shows running jobs first, pending jobs in execution order, a circular batch indicator, and recent analyses. Finished and cancelled entries occupy one line. Use a row's right-hand **X** to cancel it. Jobs run serially. Rerunning creates a new run ID and preserves previous output.
6. Browse processes, network records and files in the sidebar. The main table shows matching results; drag a column edge to resize it or double-click the edge to fit its header and widest value across the filtered results, including rows outside the viewport. Scroll normally for vertical movement and Shift-scroll for horizontal movement. The table omits Source scan, Audit, Cmd, File output, Handles, Offset and Wow64 columns, and shows timestamps as `hh:mm:ss (dd-mm-yyyy)(+hh:mm)`. Details retain all fields and original timestamps in a wrapping layout. Drag the horizontal divider to enlarge the bottom details pane. Both the results and browser lists have scrollbars. Data text supports selection and Ctrl+C, and field/JSON copy buttons are available. Raw JSON supports expansion and collapse. Process details link to saved parent and child records.
7. Click an artifact's text to open its matching completed results. Its separate dropdown arrow lists matching analyses for the evidence OS. Check some and **Queue selected**, **Queue all**, or review arguments before queuing. The toolbar **Back** button restores prior pages and artifact scopes. Bookmarks retain run/row identity through sorting and filtering; bookmark rows have a compact **Open** action. **File > Close case** saves notes and releases the case when its queue is idle.
8. Export the filtered results as CSV, or export an HTML case report containing evidence fingerprints, analysis provenance and annotated records. CSV exports quote fields and neutralize spreadsheet formulas in string values.

Process columns follow Process, PID, PPID, SessionID, Threads, Path, CreateTime and ExitTime order when those fields are available. Network columns follow PID, Target, Source, Protocol, State, Owner and Created. Target combines the remote address and port; Source combines the local address and port. IPv6 endpoints use brackets. Numeric columns start narrower, and the files table's single Name column fills the table width. Parent-process links use blue underlined text in both results and details.

**Case info** verifies an acquisition against its imported SHA-256. Verification results persist. Changed size or modification time blocks new analyses until verification succeeds; a failed hash check blocks analysis even if metadata appears unchanged. These checks cannot prevent another program from modifying an image during a plugin run. Use stable, read-only acquisitions for investigations.

## Case storage

```text
case-directory/
  case.volgui.json       case, evidence, run history and annotations
  case.sqlite            completed scan records and search indexes
  case.sqlite-wal        SQLite write-ahead log while connections are active
  .volgui.lock           exclusive writer lock while the case is open
  analyses/
    <run-uuid>/
      stdout.json        original CLI output
      stderr.log         original CLI diagnostics
      ...                files produced by the plugin
```

The manifest is replaced atomically. Completed records are committed to SQLite in transactions. Saved JSON output from older cases is imported once on a background worker, without rerunning scans or reading the acquisition. After import, result browsing and reports use the database. Raw CLI output remains available for provenance. Close the application before copying a case directory so SQLite has checkpointed its log. Evidence paths remain absolute references; copying a case does not copy its images. Reopening after an interruption marks queued and running jobs as interrupted and never silently restarts them.

Notes save when you select another artifact or close the application, and can also be saved explicitly. CSV/report generation runs in a background worker. Exports cannot replace a case manifest, its saved analysis output, or a registered evidence file.

Open directly into a case:

```powershell
cargo run --bin volgui -- --case "D:\Cases\Investigation 42"
```

## Validation

```powershell
cargo fmt --check
cargo check --all-targets --features test-engine
cargo test --features test-engine
cargo test -p accesskit_windows --lib destroyed_window
cargo clippy --all-targets --features test-engine -- -D warnings
```

`test-engine` builds a test-only CLI fixture for exercising process cancellation, nonzero exits, malformed output, literal arguments, large diagnostics and generated artifacts. Normal builds include only the application.

The Windows accessibility dependency has a [local teardown fix](vendor/accesskit_windows/PATCH.md). Its regression test calls a retained COM provider after destroying the native window and checks that it returns an error without aborting.

An optional integration test invokes a real, separately installed engine:

```powershell
$env:VOLGUI_TEST_VOLATILITY = 'D:\Repos\vol-windows-x64\vol.exe'
cargo test --features test-engine supplied_volatility_build -- --ignored --nocapture
```

That test uses `frameworkinfo.FrameworkInfo`, which does not require a memory layer. A compatible capture and symbols are still needed to validate real process, registry, network and extraction results.

The `validate_engine` example creates a small reviewable case with a real engine invocation. It can also import a capture and run one specified plugin. The `run_plugin` example runs one plugin against an existing case without repeating its evidence hash. Both use offline mode.

```powershell
cargo run --example validate_engine -- <vol-executable> <new-case-directory>
cargo run --example validate_engine -- <vol-executable> <new-case-directory> <capture-path> banners.Banners
cargo run --example run_plugin -- <case-directory> <vol-executable> windows.info.Info
```

## Foundation boundaries

This implementation provides generic plugin execution and inspection. The sidebar's Windows shortcuts do not infer an operating system or fabricate findings. Plugins that require additional inputs need those inputs in their argument field. Browser-history recovery and clipboard analysis depend on suitable plugins in the installed engine.

JSON ingestion currently accepts up to 128 MiB and one million rows per scan. The UI queries SQLite on workers, debounces text searches, keeps lightweight ordered record IDs, and fetches visible row data in batches with a cache of about 1,024 records. Results use continuous virtual scrolling rather than page-sized full-table rendering. Cross-plugin semantic correlation beyond artifact grouping, cross-case indexing, automated threat scoring, evidence relocation and installer packaging remain future work.

For native layout and scrolling checks without a capture, `cargo run --example seed_workspace -- <new-case-directory>` generates a clearly labelled synthetic case with 5,000 processes, 10,000 network records, 50,000 files and two registry scans.

See [the application design](docs/architecture.md) for module boundaries and tradeoffs.
