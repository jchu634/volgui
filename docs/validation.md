# Validation

The [CI workflow](../.github/workflows/ci.yml) runs on pushes to `main` and on pull requests. Tests and the Windows accessibility regression share one Windows job to reuse compiled dependencies. Cargo commands use the committed lockfile. Run formatting, compilation checks, and Clippy locally alongside the tests:

```powershell
cargo fmt --all --check
cargo check --locked --all-targets --features test-engine
cargo test --locked --features test-engine
cargo test --locked -p accesskit_windows --lib destroyed_window
cargo clippy --locked --all-targets --features test-engine -- -D warnings
```

`test-engine` builds a test-only CLI fixture for exercising process cancellation, nonzero exits, malformed output, literal arguments, large diagnostics and generated artifacts. Normal builds include only the application.

The Windows accessibility dependency has a [local teardown fix](../vendor/accesskit_windows/PATCH.md). Its regression test calls a retained COM provider after destroying the native window and checks that it returns an error without aborting.

An optional integration test invokes a real, separately installed engine:

```powershell
$env:VOLGUI_TEST_VOLATILITY = 'C:\Tools\Volatility\vol.exe'
cargo test --features test-engine supplied_volatility_build -- --ignored --nocapture
```

That test uses `frameworkinfo.FrameworkInfo`, which does not require a memory layer. A compatible capture and symbols are still needed to validate real process, registry, network and extraction results.

The `validate_engine` example creates a small reviewable case with a real engine invocation. It can also import a capture and run one specified plugin. The `run_plugin` example runs one plugin against an existing case without repeating its evidence hash. Both use offline mode.

```powershell
cargo run --example validate_engine -- <vol-executable> <new-case-directory>
cargo run --example validate_engine -- <vol-executable> <new-case-directory> <capture-path> banners.Banners
cargo run --example run_plugin -- <case-directory> <vol-executable> windows.info.Info
```

## Synthetic case

For native layout and scrolling checks without a capture:

```powershell
cargo run --example seed_workspace -- <new-case-directory>
```

This generates a labelled synthetic case with 5,000 processes, 10,000 network records, 50,001 files, file and non-file handles, recovered browser data, registry keys and values, and multiple cache variants. Select PID 1 and open Handles to inspect File, Key, Mutant and Event objects. Select its History file child, enable Contents, choose SQLite tables, and inspect the visits table. Browser activity shows parsed history, a search and a saved session tab. Registry can reuse saved root and Microsoft subkey reads without an engine. Global string search for `Synthetic` should return a UTF-8 match in fixture.raw. Text/hex paging and Show in Files remain available.

In Network, check the native data table with all 10,000 records. Sort PID in both directions, select rows with the mouse and Home/End keys, scroll beyond the initially cached rows, drag a column boundary, and double-click it to fit the contents. After scrolling away from a selected row, click both cell text and empty row space and confirm the viewport stays in place while details load. Repeat on partially clipped rows at the top and bottom of the viewport, in both selection directions. After releasing a click or text drag, move the pointer over either viewport edge without holding a button; the table must not auto-scroll. Home/End should still reveal the selected row, and dragging text should still select it. Search for a missing value to check the empty message, then clear the search. In New analysis, check group and individual checkboxes, shift selection, previously run plugins, and Options. The SQLite preview uses native columns while retaining its read-only 100-row pages.

`tests/investigation.rs` exercises native job persistence/export, evidence separation,
browser recovery queues, history/search parsing, offsets across string scan chunks,
unaligned UTF-16, cancellation and result limits, all handle types, registry query
arguments, and read-only SQLite paging. Browser parser unit tests cover timestamps,
provider host validation, selected session navigation and tab/window closure.

## Browser memory validation

Use a separate output case to validate an existing capture without changing the
source case or repeating its evidence hash:

```powershell
cargo run --locked --example validate_browser -- <source-case-directory> <new-case-directory> <vol-executable> [PID ...]
```

The example imports the latest completed process and command-line inventories,
recovers the selected browser PIDs or all browser/content PIDs when none are given,
then executes the same native browser analysis as the UI. The new case retains
all dump files, mapping records and browser findings. `browser.csv` is exported
for review. The stored evidence fingerprint comes from the source case; metadata
is checked, but this command does not repeat a full evidence hash.

Reparse existing dumps with the current implementation:

```powershell
cargo run --locked --example run_plugin -- <case-directory> <vol-executable> volgui.browser.Activity
```

In the app, open the output case, choose Browser activity, then Analyze recovered
data. Filter for a known phrase and verify its PID, process role and virtual
address. Choose View URL bytes and compare the retained bytes to the URL. Repeat
with Tor searches and a website URL, and check the source command line identifies
the Tor installation. Bookmark and export a finding, then reopen the case.

Automated tests cover each requested search provider and its query parameter,
URL decoding, false provider hosts, templates, autocomplete exclusions, UTF-16,
chunk boundaries, mapping gaps, masked kernel mappings, occurrence counts,
Tor parent attribution, multiple file handle owners, evidence separation,
completed dump reuse, persistence and CSV export.
