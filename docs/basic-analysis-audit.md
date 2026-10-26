# Basic analysis audit

Basic analyses supply a dedicated investigation view or one of its recovery pipelines. System information is basic as a useful preprocessing overview. Other generic result tables or artifact shortcuts alone do not qualify an analysis as basic. Bulk file recovery is explicitly extended because it attempts a dump for every file. Extended analyses remain available through Show extended analyses.

| Analysis IDs, with OS variants grouped | Consumer | Decision |
| --- | --- | --- |
| `volgui.network.Investigation` | Network view | Basic |
| `volgui.downloads.Investigation` | Download investigation view | Basic |
| `volgui.browser.Activity` | Browser activity view | Basic |
| `volgui.files.Recovery` | Files view, bulk dump attempts for every file | Extended |
| `windows.registry.AllSubkeys` | Registry tree, expands to recursive PrintKey | Basic |
| Windows/Linux/macOS PsList and PsTree; Windows PsScan | Processes tree; Windows recovery inventories and download correlation | Basic |
| Windows CmdLine | Application, browser, network and download recovery inputs | Basic |
| Windows ADS, PsXView and DllList | Download investigation inputs | Basic |
| Windows NetScan and NetStat; Linux Sockstat; macOS Netstat | Network view; Windows correlation inputs | Basic |
| Windows FileScan and DumpFiles; Linux/macOS Lsof | Files view and recovery | Basic |
| Windows Handles | Process file children, Files view and network correlation | Basic |
| Windows PrintKey, HiveList and HiveScan | Registry tree and hive selection | Basic |
| Windows VadInfo and Memmap | Process/browser memory recovery inputs | Basic |
| Windows Consoles and CmdScan | Network investigation inputs | Basic |
| Windows Info | Useful system information overview | Basic |
| Linux/macOS Bash | Generic command history shortcut only | Extended |
| Windows Malfind | Generic memory scan shortcut only | Extended |
| Windows Modules; Linux/macOS Lsmod | Generic loaded modules shortcut only | Extended |
| Windows Sessions | Generic user sessions shortcut only | Extended |
| `volgui.application.Memory` | Process Memory view, requires a chosen PID | View only, excluded from both chooser modes |

The chooser also excludes `volgui.strings.Search` if supplied in a catalog. It requires a search term and belongs to the Global string search view.

Evidence: `Workspace::group_runs` routes results by artifact group; `render_results` selects the dedicated process/file/registry trees; `render_workspace` selects the memory and network views. Recovery dependencies are declared in `analysis/application.rs`, `analysis/browser/memory.rs`, `analysis/files.rs`, `analysis/network.rs`, and `analysis/downloads.rs`. Registry records are handled in `analysis/registry.rs` and the registry tree.

The native analysis catalog retains the process-memory entry for descriptions and existing analysis history. Chooser filtering does not affect view-triggered runs or retry preparation.

Job completion refreshes results already in the current scope without selecting the finished run or navigating to its results.
