# Building and running

Build with a current Rust toolchain and the Windows C++ build tools required by GPUI.

```powershell
cargo build --release
```

#### Regenerating Logos

If the logo: `logo.svg` is changed.
Regenerate the icons using:

```powershell
magick -background none logo.svg -resize 256x256 -define icon:auto-resize=256,128,64,48,32,24,16 assets/app.ico
```

## Running

The application is written to `target/release/volgui.exe`.
To build and run a development version:

```powershell
cargo run --bin volgui
```

Browser and application memory recovery use user-memory-only dumps when the
selected vol-rs build advertises `--user-memory` in Memmap's help.\
Select the updated CLI and click **Validate and save** to detect support.\
Older engines use full dumps, and existing complete full or scoped dumps remain reusable.

VolGUI neither bundles nor copies Volatility.
