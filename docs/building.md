# Building and running

Use a current Rust toolchain and the Windows C++ build tools required by GPUI.

```powershell
cargo build --release
cargo run --bin volgui
```

Install Volatility 3 or vol-rs separately. Select the CLI in Settings and click **Validate and save**. Engines advertising Memmap's `--user-memory` option use smaller user-only dumps for browser and application recovery. Older engines use full dumps; compatible completed dumps remain reusable.

## Regenerate icons

After changing the logo, run:

```powershell
magick -background none logo.svg -resize 256x256 -define icon:auto-resize=256,128,64,48,32,24,16 assets/app.ico
```
