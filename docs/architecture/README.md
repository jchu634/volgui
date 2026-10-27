# Technical architecture

- [Case storage ownership and publication](authoritative-case-design.md)
- [Analysis queue and background persistence](analysis-queue-design.md)
- [Application memory and shared investigation services](application-memory-design.md)
- [Download investigation](download-investigation-design.md)
- [Quarantined threats](quarantine-design.md)
- [File recovery and process file integration](file-recovery-design.md)
- [Network investigation](network-design.md)
- [Virtual hex editor](hex-editor-design.md)
- [Tree detail columns and loaded modules](tree-details-design.md)
- [Analysis performance measurements](analysis-performance.md)
- [Job profiling and Network collection bottlenecks, 27 October 2026](job-profile-2026-10-27.md)
- [Job optimizations and coverage warnings](job-optimizations-2026-10-27.md)

## Source layout

- `src/ui/` owns workspace state, navigation, dialogs and background actions.
- `src/ui/views/` renders workspace screens and record details.
- `src/ui/components/` provides shared tables, trees and content panels.
- `src/lib/` implements case storage, engine integration, result handling and settings. `src/lib.rs` exports these modules.
- `src/lib/analysis/` implements native recovery, correlation, registry helpers and string search.

Views share workspace state. Actions collect and query results on background workers; rendering uses loaded state. Analysis jobs use a shared cancellable queue with two simultaneous jobs by default, configurable in Settings.
