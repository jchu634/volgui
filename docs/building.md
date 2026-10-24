# Building and running

Build with a current Rust toolchain and the Windows C++ build tools required by GPUI.

```powershell
cargo build --release
```

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
