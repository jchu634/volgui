# VolGUI

A native Rust/GPUI workspace for investigating memory captures with separately installed Volatility 3 or vol-rs engines.

VolGUI queues analyses and stores results, evidence fingerprints, recovered outputs and bookmarks in cases. Engines and acquisition images remain external.

## Get started

Download the Windows application from [Releases](https://github.com/jchu634/volgui/releases).
Point it to a engine, select it in Settings, create a case and add a memory capture.

## Investigation views

| View                   | Data                                                                                    |
| ---------------------- | --------------------------------------------------------------------------------------- |
| Processes              | Process trees, command context, handles and file children.                              |
| Network                | Socket graph/table, endpoint details, command correlation and recovered configurations. |
| Files                  | Directory trees, extraction, recovery status and content inspection.                    |
| Download investigation | Download origins, execution candidates and related sockets.                             |
| Quarantined threats    | Defender metadata, antivirus folder candidates and related processes/downloads.         |
| Browser activity       | URLs, searches, recovered history and saved sessions.                                   |
| Process Memory         | Text recovery for a PID, source addresses and hex inspection.                           |
| Registry               | Hive/key trees, typed values and targeted or recursive collection.                      |
| Global string search   | Literal UTF-8/UTF-16 matches with offsets and context.                                  |
| Bookmarks              | Saved record annotations.                                                               |

Findings retain sources and support CSV export. Recovered files can be inspected as hex, text or read-only SQLite tables. Recovery depends on captured bytes; strings, filename matches and configurations alone do not prove execution or a connection.

Specialized recovery requires Windows evidence. Engine plugins also provide Linux and macOS views. Scroll positions persist within a session and reset when closing the app or switching cases.

## Documentation

- [Building and running](docs/building.md)
- [Case storage](docs/case-storage.md)
- [Validation](docs/validation.md)
- [Analysis details](docs/analysis-details.md)
- [Architecture](docs/architecture/README.md)
