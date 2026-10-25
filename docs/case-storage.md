# Case storage

Create a case by choosing its parent location and entering a case name. VolGUI creates a new folder named after the case. Existing folders are never replaced.

```text
chosen-location/
  case-name/
    case.sqlite          authoritative case database, format v2
    case.sqlite-wal      SQLite write-ahead log while connections are active
    .volgui.lock         exclusive application writer lock
    objects/
      chunks.pack        compressed, shared SHA-256 chunks
      .writer.lock       serializes binary publication
    analyses/
      <run-uuid>/        temporary CLI capture until archived
```

SQLite owns case metadata, evidence fingerprints, analysis history, bookmarks, immutable observations, entity facts, output hashes and ordered binary manifests. No JSON case manifest is written. This pre-alpha format deliberately rejects older cases without converting or deleting them. Open the case folder or its `case.sqlite` file.

Analyses append observations to the case. Repeated identical findings share an immutable payload while retaining each run and source-row reference. Identifiable entities accumulate facts from multiple analyses. Conflicting facts retain their provenance, and ambiguous identities remain separate. The in-memory workspace holds a snapshot of database metadata, not a second persistent source of truth.

Current identity adapters associate process inventories and command lines conservatively, preserve handle ownership, and associate Windows file objects by explicit address space and object address. Other findings remain independent observations until an adapter can establish their identity safely. Enriched fields and conflicting values include their contributing observations and run-row sources in the details view.

Numeric memory-map ranges retain their immutable records and literal search, without expanding each range into general entity-fact rows or trigram text postings. This avoids indexing millions of numeric ranges as ordinary text findings.

Each archived output has a SHA-256 digest of its complete bytes. Files are split into 4 KiB chunks, each independently identified by SHA-256 and compressed into the managed pack. Identical chunks are shared across different files and process dumps. Full kernel and user bytes are retained. Different paths, runs and cache variants preserve separate provenance even when their bytes match.

Ingestion verifies existing chunks before reuse and synchronizes pack bytes before committing database references. Only after publication does it remove unchanged staging files. A failed archive leaves the capture available. A crash can leave unused pack bytes, but not committed references to unpublished chunks. Automatic pack garbage collection is not implemented.

Hex and browser parsers read verified chunks directly using logical dump offsets. Saving an output or materializing it for SQLite/ImHex additionally checks its complete SHA-256. Temporary viewer files live outside the case and are disposed when their consumer closes. The output list and case report expose recorded file hashes. A hash records identity; verification on access detects damaged bytes and fails closed.

Evidence images remain external references with import-time SHA-256 fingerprints and explicit integrity verification. Copying a case does not copy its acquisition files. Close the application before copying the whole case directory so SQLite checkpoints its log. Keep the database and `objects` directory together.

Reopening marks queued or running analyses interrupted and does not restart them. Queue clearing dismisses entries while preserving observations, history and binary provenance. Reports and CSV exports run on background workers. Exports cannot replace the database, its sidecars, managed binary storage, captured analysis output or registered evidence.

The external CLI still creates complete staging files before archiving. Chunk sharing reduces retained storage; it does not eliminate peak disk use during acquisition recovery. See [the design rationale](authoritative-case-design.md) for ownership, alternatives and validation requirements.

The current object manifest supports individual outputs up to 32 GiB. A larger output is rejected before archival and its capture is retained. This limit applies to a single logical file, not the total case size.
