# Analysis details

This reference lists the plugins and recovery processing that produce investigation data. Plugin availability depends on the selected engine. Specialized recovery workflows currently require Windows evidence.

Inventories are analysis inputs, not automatic case-opening scans. Requests reuse compatible results and can collect missing inputs.

## Processes

### Inputs

- Windows: `windows.pslist.PsList`, `windows.pstree.PsTree` and `windows.psscan.PsScan`.
- Linux: `linux.pslist.PsList`, `linux.pstree.PsTree` and process inventories such as `linux.psaux.PsAux` when available.
- macOS: `mac.pslist.PsList` and `mac.pstree.PsTree`.
- Windows command context can come from `windows.cmdline.CmdLine` through process identity enrichment.

### Collection

Handle collection uses `windows.handles.Handles --pid PID`, `linux.lsof.Lsof --pid PID` or `mac.lsof.Lsof --pid PID`. Process file dumping uses `windows.dumpfiles.DumpFiles --pid PID`. Process-memory recovery is described separately below.

### Processing

Process observations are associated conservatively using evidence, object address or creation time where available. Ambiguous PID matches remain separate. File handles are associated with processes by PID; all collected handle types remain available. A handle establishes a reference to an object, not that the object's contents are recoverable.

## Network

### Inputs

The Windows correlation analysis consumes available results from:

- `windows.netscan.NetScan`
- `windows.netstat.NetStat`
- `windows.pslist.PsList`
- `windows.cmdline.CmdLine`
- `windows.cmdscan.CmdScan`
- `windows.consoles.Consoles`
- `windows.handles.Handles`

Linux/macOS socket data can come from `linux.sockstat.Sockstat`, `linux.sockscan.Sockscan` and `mac.netstat.Netstat` when supported. These do not enable the Windows native correlation workflow.

### Collection

`volgui.network.Investigation` collects missing available Windows preprocessing inventories, then performs native correlation and configuration recovery. Compatible completed or preceding queued inventories can be reused.

### Processing

Correlate socket, process, command and handle records to recover UNC shares and explicit connection commands. Credentials are recovered only when explicitly present in a network-drive command, with scope retained for the relevant command and share. Preserve exact local/remote socket pairs and source occurrences.

Independently scan acquisition bytes for structurally validated legacy Meterpreter TCP configurations, validating session structure, transport URL, padding, exit function, UUID and timeouts. Also validate stock Cobalt Strike Beacon HTTP(S) typed configurations with plaintext or default single-byte XOR keys. Validate field types/lengths, required settings, zero termination/padding, RSA public-key structure and host/URI pairs. Historical Meterpreter configurations from completed download reports can also contribute findings.

Correlation is bounded at 20,000 findings; configuration recovery at 2,000 configurations. Coverage and unavailable inventories are recorded. A recovered configuration is unattributed and does not prove execution or a connection. Arbitrary raw credential text is not scanned by this analysis.

Supported explicit connection syntax includes Ncat/netcat, socat TCP operands, PowerShell/.NET TcpClient constructors, Python socket connection calls and Bash `/dev/tcp` redirections. Ncat listen addresses are not treated as remote targets; unsupported or ambiguous option forms are omitted. Numeric ports and literal IPs/hostnames are required. Variables, encoded scripts and general program execution are not evaluated. Hostnames remain hostname references without DNS resolution.

### Network process attribution

`volgui.network.ProcessAttribution` is a separate job under Network, automatically queued by Network investigation when the engine supports VAD regex discovery, Memmap and VadInfo. It is also available independently in the chooser. Optional `--pid PID` scans one process and works without VAD regex discovery.

The job pins process/command inventories, discovers candidate PIDs through explicit program/configuration markers, and reuses compatible completed Memmap dumps and VAD inventories from other analyses. It collects missing inputs for those candidates. It scans readable user VADs, including image and read-only regions, without widening Browser or Process Memory defaults. Virtual page reconstruction can validate configurations fragmented in acquisition bytes. Findings retain source runs, process identity, virtual and dump addresses, VAD protection/file, encoding and configuration hashes. Source bytes opens the pinned dump at its dump offset.

Coverage is limited to processes discoverable through PsList and readable engine mappings. Unknown encryption, obfuscation or unsupported program syntax can prevent discovery. Bounds are 256 processes, 20,000 findings, 1 GiB per process and 4 GiB total scanned cores, with bounded overlapping context. Missing inputs, gaps and limits are reported. Later process collections invalidate automatic reuse through an input fingerprint. Process-memory presence does not establish a successful connection, execution or exclusive ownership.

Cobalt Strike support is deliberately limited to stock HTTP(S) TLV layouts and keys `0x00`, `0x2e` and `0x69`. It does not identify every Beacon version, modified setting indexes, other transport types or arbitrary encryption. Sliver and Havoc configurations are not currently decoded. See [format references and validation](architecture/network-attribution-design.md).

## Files and document recovery

### Inputs

Windows recovery consumes `windows.filescan.FileScan` and available `windows.handles.Handles` results. Linux/macOS file references can come from `linux.lsof.Lsof` and `mac.lsof.Lsof`. Other file inventories retain their engine-provided data.

### Collection

Individual extraction uses `windows.dumpfiles.DumpFiles` for the source file object and address space. Bulk `volgui.files.Recovery` collects missing `windows.filescan.FileScan` and available `windows.handles.Handles`, then requests a distinct `windows.dumpfiles.DumpFiles` extraction for each eligible object. Compatible completed extractions can be reused.

**Discover executable paths** in Files and documents runs `volgui.files.PathReferences`. It reads the evidence once for Windows `.exe` paths in UTF-8, UTF-16LE and UTF-16BE, without FileScan prerequisites or extraction jobs. This analysis is also available as **Executable path discovery** in the basic analysis chooser. Findings appear in the file tree as **Path reference only**, including when Show unavailable files is off, with evidence offsets and encoding retained in their records. Use this to find executable references when bulk recovery would queue too many jobs.

### Processing

Associate extraction outcomes by evidence, address space and object address. Retain original source records, extraction runs and diagnostics. A recovered output takes precedence over an unsuccessful retry. Unknown recovery status remains distinct from confirmed empty, failed or unsupported extraction. Multiple cache variants remain distinct, and recovered contents may be partial.

Bulk recovery also scans acquisition bytes for executable-path references, capped at 10,000. These references do not prove file presence or recoverability. `windows.mftscan.ADS` records describe streams and are not treated as recoverable file objects.

## Download investigation

### Inputs

- `windows.pslist.PsList`
- `windows.psscan.PsScan`
- `windows.cmdline.CmdLine`
- `windows.dlllist.DllList`
- `windows.malware.psxview.PsXView`
- `windows.filescan.FileScan`
- `windows.mftscan.ADS`
- `windows.netscan.NetScan`
- `windows.netstat.NetStat`

Existing `volgui.browser.Activity` findings can also supply download records or executable-URL leads.

### Collection

`volgui.downloads.Investigation` automatically queues every missing unfiltered source inventory ahead of the report. Completed results and preceding queued or running jobs for the same evidence are reused. Unsupported prerequisites prevent queuing; missing or failed prerequisites fail the investigation instead of producing a coverage warning. When supported, targeted `windows.dumpfiles.DumpFiles` jobs recover browser profile files before native parsing. A separate browser-memory scan is not required for profile parsing.

### Processing

Parse NTFS `Zone.Identifier` origins and cached Chromium download history. Match filenames and executable paths against process candidates, command lines and loaded executable paths. Associate socket records while retaining uncertainty about PID reuse and missing ownership.

Scan acquisition bytes for residual process candidates only after validating a supported Windows x64 layout against collected process records. Keep download evidence, executable-URL leads, filename matches, residual candidates and PID-only socket associations distinct, with source records or byte offsets.

The main report is capped at 10,000 findings and includes coverage diagnostics. Filename matches do not prove execution, and ports alone do not establish a reverse shell. Meterpreter configuration recovery belongs to Network.

## Browser activity

### Inputs

Require unfiltered `windows.pslist.PsList`, `windows.cmdline.CmdLine` and `windows.filescan.FileScan` results completed or queued before browser analysis. Existing `windows.handles.Handles` records can supply profile ownership.

### Collection

The browser recovery action collects the three preprocessing inventories first. A direct `volgui.browser.Activity` chooser request requires those inventories to be completed or already queued.

Recovery identifies browser/content PIDs and requests `windows.memmap.Memmap --pid PID --dump`. Supported engines use `--user-memory`; compatible complete full or user-only dumps can be reused. Targeted `windows.dumpfiles.DumpFiles` jobs recover recognized profile history/session files. The native parser is `volgui.browser.Activity`.

### Processing

Validate mapping metadata and scan user-space process bytes for UTF-8 and UTF-16 URLs. Group exact URLs per PID, retain occurrence counts and extract search terms using provider-specific host, path and parameter rules. Incomplete strings do not produce search terms. Known automated Edge annotation queries are labelled separately.

Parse recovered Chromium/Mozilla history and supported saved-session formats, normalize timestamps and apply session navigation/closure records. Keep memory strings, history visits and saved tabs distinct. Multiple handle owners remain related PIDs rather than an invented single historical owner.

Limits are 10,000 unique memory URLs per process and 100,000 report rows. Corrupt, encrypted or unavailable data produces diagnostics. Memory strings do not prove visits, and saved sessions do not prove that the browser was running at capture time.

## Process memory

### Inputs

Use unfiltered `windows.pslist.PsList` and `windows.cmdline.CmdLine` for process identity and command context.

### Collection

For the chosen PID, `volgui.application.Memory` automatically collects missing preprocessing inventories, then requests `windows.vadinfo.VadInfo` and `windows.memmap.Memmap` mappings/dumps. Exact source runs are pinned. Compatible completed dumps can be reused, and supported engines request user-memory-only collection.

### Processing

Validate mappings and user-address limits, intersect mapped ranges with private writable memory regions, then scan UTF-8, UTF-16LE and UTF-16BE text. Candidates require at least eight characters, four ASCII letters or digits, and at least half ASCII characters. `--contains` optionally applies a literal ASCII-case-insensitive filter. Shifted UTF-16 interpretations at adjacent offsets can share a candidate while retaining alternate encoding/address metadata.

Retain PID, encoding, source runs, virtual addresses, dump byte spans and boundary diagnostics. Limits are 50,000 rows, 32 MiB total text and 64 KiB per fragment. Text can include old edits, resources and partial buffers. Current tab, save state and document association remain unknown; text entirely in other scripts can be omitted by the ASCII requirements.

## Registry

### Inputs

Hive discovery uses `windows.registry.hivelist.HiveList` and `windows.registry.hivescan.HiveScan`. Other registry findings, such as `UserAssist`, `Amcache` and `ShimcacheMem`, retain their own plugin semantics.

### Collection

Key collection uses `windows.registry.printkey.PrintKey` with a hive offset and relative key path, optionally `--recurse`. Matching completed queries for the same evidence can be reused. `windows.registry.AllSubkeys` expands into `windows.registry.printkey.PrintKey --recurse`.

### Processing

Normalize hive offsets and derive relative child-key paths for targeted collection. Key names, value types and data come from the engine's records. There is no additional native registry recovery parser.

## Global string search

Search reads the acquisition directly.

`volgui.strings.Search` scans bounded chunks for the literal term encoded as UTF-8, UTF-16LE and UTF-16BE, including unaligned UTF-16 and matches crossing chunk boundaries. Optional case folding applies only to ASCII characters. Retain encoding, evidence-file byte offsets and surrounding context.

Search terms are limited to 4,096 UTF-8 bytes and results to 10,000 hits. Byte offsets do not establish process ownership or virtual addresses.

## Other artifact analyses

These consume the selected engine plugin's results without an additional specialized recovery pass. Collection occurs when the corresponding analysis is requested; no separate preprocessing inventory is required.

| Data | Representative plugins | Further processing |
| --- | --- | --- |
| Memory scan results | `Malfind`, `PsXView`, `HollowProcesses`, `YaraScan`, `VadYaraScan` and other malware plugins | No automatic malware verdict. |
| System information | `Info`, `Banners`, `BootTime`, `CrashInfo`, `Kmsg`, `Dmesg` | Retain engine-provided findings. |
| Command history | `CmdLine`, `CmdScan`, `Consoles`, `Bash`, `Envars` | Network/download analyses separately correlate supported records as described above. |
| Loaded modules | `DllList`, `LdrModules`, `Modules`, `ModScan`, `Lsmod`, `Library_List`, `UnloadedModules` | Download analysis separately consumes executable paths. |
| User sessions | `Sessions`, `GetSids`, `GetServiceSids` | Retain engine-provided findings. |
| Other artifacts | Remaining engine plugins, including standalone `Memmap`, `VadInfo` and `ADS` results | Recovery workflows can consume these records as described above. |

Short plugin names in this table describe engine plugin families; exact IDs depend on the engine and operating system. Bookmarks and case-management screens do not run forensic analyses.
