# Architecture

- [Case storage and publication](authoritative-case-design.md)
- [Analysis queue](analysis-queue-design.md)
- [Application memory and shared services](application-memory-design.md)
- [Download investigation](download-investigation-design.md)
- [Quarantined threats](quarantine-design.md)
- [File recovery](file-recovery-design.md)
- [Network investigation](network-design.md)
- [Network process attribution](network-attribution-design.md)
- [Partial matches and recovery limits](partial-matches-design.md)
- [Tree detail columns](tree-details-design.md)
- [Session scroll state](scroll-state.md)

The UI owns workspace state, navigation and rendering. Background actions query and collect results. Shared components provide tables, trees and content panels. Library modules own storage, engine integration and native analysis. A cancellable queue runs two jobs by default, configurable in Settings.
