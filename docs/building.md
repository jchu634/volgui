# Building and running

Build with a current Rust toolchain and the Windows C++ build tools required by GPUI.

```powershell
cargo build --release
```

Windows builds embed `assets/app.ico` as the executable and window icon. It is
generated from the root `logo.svg`. After changing the logo, regenerate it with
ImageMagick before building:

```powershell
magick -background none logo.svg -resize 256x256 -define icon:auto-resize=256,128,64,48,32,24,16 assets/app.ico
```

## Manual nightly builds

Once the workflows are on the default branch, open **Actions > Nightly build > Run workflow** on GitHub and select the branch to build. The [nightly workflow](../.github/workflows/nightly.yml) uses stable Rust to build the Windows x86_64 release executable from the committed lockfile.

Each successful run publishes a GitHub prerelease tagged `nightly-<run-id>-<attempt>` for the built commit. Download `volgui-nightly-windows-x86_64.zip` from the repository's Releases page. The ZIP contains `volgui.exe`, build instructions, the source commit and build details in `BUILD.txt`, and an executable checksum in `SHA256SUMS`. Rerunning the workflow creates a separate prerelease.

The same files remain available in the completed run's `volgui-nightly-windows-x86_64-<commit>-<attempt>` artifact for 30 days. Builds run only when triggered manually.

## Running

The application is written to `target/release/volgui.exe`. To build and run a development version:

```powershell
cargo run --bin volgui -- --volatility C:\Tools\Volatility\vol.exe
```

Volatility 3 and [vol-rs](https://github.com/daffainfo/vol-rs) are supported. To use vol-rs:

```powershell
cargo run --bin volgui -- --volatility D:\vol-rs-v1.0.2-windows-x86_64
```

Development builds optimize VolGUI's processing code, SHA-256, byte searches,
LZ4 and the bundled SQLite engine. These paths handle large dumps even while the
UI is being developed. GPUI keeps its normal development settings. Release builds
use Cargo's release settings for the whole application. See the
[analysis performance investigation](architecture/analysis-performance.md) for measurements
and a repeatable import benchmark.

Select either executable or its installation directory in Settings. If a directory contains both engines, `vol` takes precedence; select `vol-rs.exe` explicitly to use vol-rs. The existing `--volatility` option accepts either engine.

Browser and application memory recovery use user-memory-only dumps when the
selected vol-rs build advertises `--user-memory` in Memmap's help. Select the
updated CLI and click **Validate and save** to detect support. Older engines use
full dumps, and existing complete full or scoped dumps remain reusable. Manual
Memmap jobs retain their requested scope. See [analysis performance](architecture/analysis-performance.md#user-memory-collection).

The executable path can also be supplied by an installer using the `VOLGUI_VOLATILITY` environment variable, or selected in **Settings**. Validated settings persist in `%APPDATA%\VolGUI\settings.json`. `VOLGUI_CONFIG_DIR` overrides that directory for portable installations or testing. No development-specific engine path is compiled into the application.

Analysis jobs run in separate CLI instances, with up to two jobs active by default.
Change **Settings > Maximum simultaneous jobs > Save job limit** to set the global
limit. Changes apply immediately; lowering the limit lets active jobs finish before
starting more. Browser parsing waits for the extraction jobs ahead of it.

Keep the external build's executable, DLLs, plugins and supporting files together. VolGUI neither bundles nor copies Volatility. Engine installation, distribution and licensing remain separate. Volatility's own CLI behavior is documented in its [official manual](https://volatility3.readthedocs.io/en/stable/vol-cli.html).

Open directly into a case:

```powershell
cargo run --bin volgui -- --case "D:\Cases\Investigation 42"
```

## Extracting individual files

Select a Windows File scan result, or a File entry from Windows Handles. In **Overview** or **Extracted files**, choose **Dump file** to extract that file, or **Dump and open in ImHex** to extract it and open the output. A previous Dump files job is not required. ImHex must be installed in its default location or available on `PATH`.

The extraction runs as a normal cancellable job against the result's source evidence. When it finishes, **Extracted files** lists the output with **Save as...** and **Open in ImHex** actions. Volatility can produce several cache files for one file object, or none if its contents are no longer cached in memory.

**Hex content** displays those bytes inside VolGUI in both the process and file views. Use **Extract and view hex** to extract the selected file without changing views, or **View hex** beside an existing extracted file. The viewer reads 256 bytes per page and shows offsets, hex bytes and ASCII. Multiple cache outputs have separate selection buttons. Completed per-file dumps are reused only for the same source evidence, object address and address space.

For an unlabelled FileScan **Offset**, the address-space button defaults to **Virtual offset**, as used on Windows 10 and later. Click it to select **Physical offset** for older Windows captures. Explicit **Offset(V)** and **Offset(P)** columns select the address space automatically. This follows Volatility's [pool scanner](https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/poolscanner.html) and [DumpFiles address options](https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/dumpfiles.html).

## Missing kernel symbols

If an analysis reports `Symbols are not available offline`, open Settings, switch
from **Offline mode enabled** to **Online symbol lookup enabled**, and click
**Validate and save**. Retry the failed analyses. Offline use requires a symbols
directory containing symbols for the exact kernel in the capture. Volatility and
vol-rs use separate default symbol locations, so switching engines may require
setting the symbols directory or downloading symbols again.

VolGUI supplies vol-rs with explicit cache and default symbols directories under
`%APPDATA%\VolGUI\cache\vol-rs` because vol-rs 1.0.2 cannot find its defaults on
Windows without Unix environment variables. `VOLGUI_CONFIG_DIR` relocates this
cache too. A symbols directory selected in Settings takes precedence.
