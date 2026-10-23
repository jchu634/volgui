# Windows teardown fix

This directory contains `accesskit_windows` 0.34.0 from crates.io, upstream
commit `c88605b96d04431f9c3c792464a0f2f253480e94`. License files come from that
commit. Cargo uses this source through `[patch.crates-io]`.

UI Automation can retain a provider while GPUI destroys its native window.
`ClientToScreen` then fails. The upstream adapter unwraps that error inside a
COM callback, which aborts because the callback cannot unwind.

The local change makes `client_top_left` fallible and propagates
`UIA_E_ELEMENTNOTAVAILABLE` through rectangle and hit-test callbacks. It does
not disable accessibility or return fabricated screen coordinates.

Run the regression with:

```sh
cargo test -p accesskit_windows --lib destroyed_window -- --nocapture
```

The test retains a real COM provider across native window destruction, checks
geometry while the window exists, then calls the same provider after teardown.
Remove this patch when a compatible upstream release handles this race.
