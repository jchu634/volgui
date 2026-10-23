# Volgui

Native GPUI-kit frontend for a separately installed Volatility 3 CLI. The GUI
does not import, embed, link to, or copy Volatility Python code. All analysis and
help requests execute the configured CLI directly, with an argument vector and
no shell. Custom/external plugin loading is outside the current scope.

## Build and run

On Windows, install Rust and Visual Studio C++ Build Tools with the Windows SDK,
then use a Visual Studio Developer PowerShell or x64 Native Tools prompt.
Run `cargo run` from this repository, or `cargo build --release` to build
`target/release/volgui.exe`.

Build the engine in its separate repository:

```powershell
cd D:\Repos\volatility3
uv venv --python 3.12 .venv-build
uv pip install --python .venv-build\Scripts\python.exe -r development\requirements-nuitka.txt
.venv-build\Scripts\python.exe development\build_nuitka.py
```

Select `D:\Repos\volatility3\build\nuitka\vol.dist\vol.exe` in the GUI.
Keep the entire `vol.dist` folder together: standalone means an executable plus
its supporting libraries, with no separately installed Python required.
The build script supports `--onefile` for a self-extracting executable; standalone
is the default to avoid extraction overhead at every invocation. It validates
the compiled engine's built-in discovery and per-analysis help before success.

Alternatively set `VOLGUI_VOL` to the executable path. A `vol/vol.exe` directory
beside the GUI executable is detected automatically; otherwise `vol` is resolved
from PATH. Engine distribution, source, license and build remain in the separate
repository. The build copies Volatility's license alongside its artifact.

## Analyse

1. Select the engine executable, an existing memory image and an output folder.
2. Choose a built-in analysis from the sidebar. Use **Options help** for its CLI
   options, then enter any required options (for example `--pid 4`). Quoted option
   values use shell-word syntax; use forward slashes for paths in this field.
3. Run the analysis. **Cancel** terminates the active process. Closing the app also
   requests termination. Diagnostics display the tail of the engine's stderr.
4. Filter the table or export full stdout as JSON. Nested results are flattened
   with indentation. The preview loads at most 32 MiB and 2,000 rows, displaying
   at most 500 matching rows. Export copies the original file without those limits.
   Failed/cancelled runs may contain partial output, which can also be exported.

Output and diagnostics use temporary files while the application is open. Export
before running another analysis or closing the app. Extracted files written by
Volatility remain in the chosen output directory.

Offline mode passes `--offline`; symbols must already be available in Volatility's
cache. Online mode may download symbols. A usable memory image and matching symbols
are required for a real analysis; none are bundled with the application.

Nuitka improves packaging portability; analysis speed improvements depend on the
workload and are not guaranteed. Build native binaries separately for each target
OS/architecture. Compiling Volatility does not change its license.
