# Case storage

```text
case-directory/
  case.volgui.json       case, evidence, run history and annotations
  case.sqlite            completed scan records and search indexes
  case.sqlite-wal        SQLite write-ahead log while connections are active
  .volgui.lock           exclusive writer lock while the case is open
  analyses/
    <run-uuid>/
      stdout.json        original CLI output
      stderr.log         original CLI diagnostics
      ...                files produced by the plugin
```

The manifest is replaced atomically. Completed records are committed to SQLite in transactions. Saved JSON output from older cases is imported once on a background worker, without rerunning scans or reading the acquisition. After import, result browsing and reports use the database. Raw CLI output remains available for provenance. Close the application before copying a case directory so SQLite has checkpointed its log. Evidence paths remain absolute references; copying a case does not copy its images. Reopening after an interruption marks queued and running jobs as interrupted and never silently restarts them.

Notes save when you select another artifact or close the application, and can also be saved explicitly. CSV/report generation runs in a background worker. Exports cannot replace a case manifest, its saved analysis output, or a registered evidence file.
