# Building and running

Build with a current Rust toolchain and the Windows C++ build tools required by GPUI.

```powershell
cargo build --release
```

## Manual nightly builds

Once the workflows are on the default branch, open **Actions > Nightly build > Run workflow** on GitHub and select the branch to build. The [nightly workflow](../.github/workflows/nightly.yml) uses stable Rust to build the Windows x86_64 release executable from the committed lockfile.

Download `volgui-nightly-windows-x86_64-<commit>-<attempt>` from the completed run's artifacts. The ZIP contains `volgui.exe`, build instructions, the source commit and build details in `BUILD.txt`, and an executable checksum in `SHA256SUMS`. Artifacts are retained for 30 days. Builds run only when triggered manually.

## Running

The application is written to `target/release/volgui.exe`. To build and run a development version:

```powershell
cargo run --bin volgui -- --volatility C:\Tools\Volatility\vol.exe
```

The executable path can also be supplied by an installer using the `VOLGUI_VOLATILITY` environment variable, or selected in **Settings**. Validated settings persist in `%APPDATA%\VolGUI\settings.json`. `VOLGUI_CONFIG_DIR` overrides that directory for portable installations or testing. No development-specific engine path is compiled into the application.

Keep the external build's executable, DLLs, plugins and supporting files together. VolGUI neither bundles nor copies Volatility. Engine installation, distribution and licensing remain separate. Volatility's own CLI behavior is documented in its [official manual](https://volatility3.readthedocs.io/en/stable/vol-cli.html).

Open directly into a case:

```powershell
cargo run --bin volgui -- --case "D:\Cases\Investigation 42"
```

## Extracting individual files

Select a Windows File scan result, or a File entry from Windows Handles. In **Overview** or **Extracted files**, choose **Dump file** to extract that file, or **Dump and open in ImHex** to extract it and open the output. A previous Dump files job is not required. ImHex must be installed in its default location or available on `PATH`.

The extraction runs as a normal cancellable job against the result's source evidence. When it finishes, **Extracted files** lists the output with **Save as...** and **Open in ImHex** actions. Volatility can produce several cache files for one file object, or none if its contents are no longer cached in memory.

For an unlabelled FileScan **Offset**, the address-space button defaults to **Virtual offset**, as used on Windows 10 and later. Click it to select **Physical offset** for older Windows captures. Explicit **Offset(V)** and **Offset(P)** columns select the address space automatically. This follows Volatility's [pool scanner](https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/poolscanner.html) and [DumpFiles address options](https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/dumpfiles.html).
