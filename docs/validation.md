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

This generates a clearly labelled synthetic case with 5,000 processes, 10,000 network records, 50,000 files and two registry scans.
