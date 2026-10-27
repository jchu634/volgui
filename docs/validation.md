# Validation

## Standard checks

[CI](../.github/workflows/ci.yml) runs on pushes to `main` and pull requests. Run:

```powershell
cargo fmt --all --check
cargo check --locked --all-targets --features test-engine
cargo test --locked --no-default-features --features test-engine
cargo test --locked -p accesskit_windows --lib destroyed_window
cargo clippy --locked --all-targets --features test-engine -- -D warnings
```

`desktop` enables the app binary by default. Tests can disable default features to avoid replacing a running executable. `test-engine` supplies a test-only CLI for cancellation, malformed output, diagnostics and artifact checks.

The [Windows accessibility patch](../vendor/accesskit_windows/PATCH.md) has a regression test for COM providers retained after window destruction.

## Real engines and captures

Set `VOLGUI_TEST_VOLATILITY` to an installed CLI before running:

```powershell
cargo test --features test-engine supplied_volatility_build -- --ignored --nocapture
```

This uses FrameworkInfo without a capture. Real artifact validation also requires compatible evidence and symbols. The examples below retain reviewable results and run offline:

```powershell
cargo run --example validate_engine -- <engine> <new-case>
cargo run --example validate_engine -- <engine> <new-case> <capture> banners.Banners
cargo run --example run_plugin -- <case> <engine> windows.info.Info
```

## Recovery workflows

Use new output cases to preserve source cases. Browser/application examples reuse saved inventories and fingerprints, check evidence metadata and avoid repeating the full acquisition hash.

```powershell
cargo run --locked --no-default-features --example validate_downloads -- <capture> <new-case> <engine> [source-case]
cargo run --locked --no-default-features --example validate_network -- <capture> <new-case> <engine>
cargo run --locked --no-default-features --example validate_application -- <source-case> <new-case> <engine> --pid PID [--contains text]
cargo run --locked --example validate_browser -- <source-case> <new-case> <engine> [PID ...]
```

These run the desktop queue expansion and native parsers, retaining sources and CSV exports. Application validation can use the same source/output case to add an analysis and reuse completed dumps. Browser validation selects all browser/content PIDs when none are supplied. Reparse saved browser dumps with:

```powershell
cargo run --locked --example run_plugin -- <case> <engine> volgui.browser.Activity
```

In each output case, inspect source records and bytes, navigate Back, bookmark/export a finding and reopen the case. Check workflow-specific limits:

- Downloads: keep origins, filename matches, residual processes and socket ownership distinct. Confirm exact PID filtering.
- Network: check endpoint pairing, graph/table filters, sidebar paging, process links and configuration source bytes. Missing ownership stays unknown.
- Process Memory: compare known text with retained bytes, encodings, virtual addresses and dump offsets. Competing copies remain separate; save state and document association stay unknown.
- Browser: compare URLs/searches with retained bytes and process identity. Memory strings, history visits and saved tabs remain distinct.

## Quarantined threats

```powershell
cargo run --locked --example seed_quarantine -- <new-case>
cargo test --locked --no-default-features --features test-engine --test quarantine
```

The seed contains benign synthetic Defender metadata, folder/process/origin candidates and a separately labelled local output. Append `--passive-only` to omit the initial quarantine report.

Set `VOLGUI_TEST_DEFENDER_ENTRY` to independently collected Defender Entries metadata, then run:

```powershell
cargo test --locked --no-default-features --features test-engine --test quarantine independently_captured_defender_metadata -- --ignored
```

Check that Scope separates capture findings from local outputs. Inspect metadata, match strength and source diagnostics. Known folders remain candidates; empty recovery does not imply antivirus blocking. Blocked local records retain their reason without claiming a confirmed cause.

Passive updates should work offline, reuse unchanged reports across reopening and refresh after a blocked output without hiding explicit capture findings. Failed/cancelled antivirus-related jobs retain status and diagnostics. Unknown targets stay unknown; explicit collection remains available.

## Synthetic UI checks

```powershell
cargo run --example seed_workspace -- <new-case>
```

The fixture includes large process, socket and file inventories, handles, modules, recovered browser data, registry data and cache variants. Check:

- Processes, Registry and Loaded modules: pinned hierarchy, column resizing, horizontal scrolling, aligned rows, keyboard navigation and expansion state.
- Files and process handles: selection, extraction variants, Show in Files, text/hex paging and read-only SQLite previews.
- Network: filtering, numeric sorting, large endpoint groups, continuous scrolling, source navigation and Back restoration.
- Browser, Registry and string search: saved findings, reusable key reads and a literal `Synthetic` match.
- Analysis chooser: group/individual selection, shift selection, previous runs and options.

Switch views and return to check scroll restoration. Restart the app to confirm session positions reset.

## Storage benchmark

```powershell
cargo test --locked --no-default-features --features test-engine --test object_store benchmark_shared_dumps_and_browser_range_reads -- --ignored --nocapture
```

This creates four temporary 64 MiB dumps with shared kernel pages. It verifies user-range bytes before/after archival and reports storage size, archival time and verified-read timings. It does not measure engine extraction or the complete browser parser. Temporary data is removed afterward.
