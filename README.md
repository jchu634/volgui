# VolGUI

A native Rust/GPUI workspace for investigating memory captures with separately installed Volatility 3 or vol-rs engines.

VolGUI queues analyses and keeps results, evidence fingerprints, recovered outputs and bookmarks in case directories. The analysis engine and acquisition images remain external to the case. Volatility is not bundled.

## Download

Download the Windows application from [Releases](https://github.com/jchu634/volgui/releases). Volatility 3 or vol-rs must be installed separately. Select the engine in Settings, create or open a case, and add a memory capture.

## Investigation views

| View | What it provides |
| --- | --- |
| Processes | Parent/child process trees, command context, collected handles and process file children. |
| Network | Socket graph and table, endpoint details, command correlation, validated Meterpreter TCP configurations and incomplete configuration candidates. Payload UUIDs, session GUIDs and ownership limits remain visible. |
| Files | Directory trees, per-file extraction, recovery status and recovered content inspection. Bulk file recovery is an extended analysis. |
| Download investigation | Download origins, filename-based execution candidates, residual process candidates and related socket records, with separate evidence labels. |
| Quarantined threats | Defender quarantine metadata, known antivirus folder candidates, process matches and download origins. Local blocked outputs have a separate scope. |
| Browser activity | URLs and searches from browser process memory, recovered history and saved sessions. |
| Process Memory | Text recovery for a chosen PID, source addresses, match navigation and a virtualized hex reader. |
| Registry | Hive/key trees and typed values, with targeted or recursive PrintKey collection. |
| Global string search | Literal UTF-8 and UTF-16 searches of the acquisition, with byte offsets and context. |
| Bookmarks | Saved record annotations for later review. |

Recovered files can be inspected as hex, text or read-only SQLite tables. Findings retain source references and support CSV export and bookmarks. Recovery depends on the bytes present in the capture; a filename match, memory string or recovered configuration does not by itself prove execution or a connection.

Scroll positions are remembered while switching views and using Back during a session. Closing the application or switching cases resets them.

The specialized recovery workflows currently require Windows evidence. Available engine plugins also supply Linux and macOS artifact views. See [Analysis Details](docs/analysis-details.md) for the plugins and recovery processing behind each analysis.

## Documentation

- [Building and running](docs/building.md)
- [Case storage and copying cases](docs/case-storage.md)
- [Validation commands and capture checks](docs/validation.md)
- [Analysis Details](docs/analysis-details.md)
- [Technical architecture](docs/architecture/)
