# Case storage

Create a case by choosing its parent location and entering a case name. VolGUI creates a new folder named after the case. Existing folders are never replaced.

```text
chosen-location/
  case-name/
    case.sqlite          authoritative case database, format v4
    case.sqlite-wal      SQLite write-ahead log while connections are active
    .volgui.lock         exclusive application writer lock
    objects/
      chunks.pack        shared, compressed 4 KiB analysis chunks
      blobs/
        <uuid>           complete ordinary files recovered by DumpFiles
    analyses/
      <run-uuid>/        temporary CLI capture until archived
```

SQLite owns case metadata, evidence fingerprints, analysis history, bookmarks, immutable observations, entity facts and output references. It also owns the shared chunk catalog and authenticated object manifests. Each output reference retains its byte count and complete SHA-256. No JSON case manifest is written. This pre-alpha format deliberately rejects older cases without converting or deleting them. Open the case folder or its `case.sqlite` file.

Analyses append observations to the case. Repeated identical findings share an immutable payload while retaining each run and source-row reference. Identifiable entities accumulate facts from multiple analyses. Conflicting facts retain their provenance, and ambiguous identities remain separate. The in-memory workspace holds a snapshot of database metadata, not a second persistent source of truth.

Current identity adapters associate process inventories and command lines conservatively, preserve handle ownership, and associate Windows file objects by explicit address space and object address. Other findings remain independent observations until an adapter can establish their identity safely. Enriched fields and conflicting values include their contributing observations and run-row sources in the details view.

Numeric memory-map ranges retain their immutable records and literal search, without expanding each range into general entity-fact rows or trigram text postings. This avoids indexing millions of numeric ranges as ordinary text findings.

Process dumps and other analysis outputs share identical 4 KiB chunks across paths and runs in `objects/chunks.pack`. Each chunk is compressed with LZ4 and identified by SHA-256. Ordered manifests retain every original byte and offset, including shared kernel mappings. Identical complete outputs share one object while retaining separate run/name provenance. This storage shares analysis outputs with each other; external acquisition images remain separate references.

Files recovered by `windows.dumpfiles.DumpFiles` remain independent ordinary files in `objects/blobs`, identified by UUID with a complete SHA-256. These files can duplicate bytes in process dumps, other recovered files and cache variants. DumpFiles diagnostics still use shared chunk storage. Exported files are complete standalone files.

Ingestion hashes outputs outside a database transaction. A cancellable per-case pack lock serializes archivers while result imports and metadata saves can continue. Buffered I/O and a publication-local chunk cache avoid repeated lookups and verification of shared pages. Bytes are synchronized before their references commit; only then are unchanged staging files removed. Failed or cancelled publication removes unpublished ordinary files and truncates the unpublished pack tail. A crash can leave unreferenced bytes; automatic garbage collection is not implemented.

Hex and browser parsers use the same logical dump offsets. Chunk readers verify the manifest on opening and verify each requested chunk before returning its bytes. Manifest entries contain pack locations, so reading requires no per-page SQL. Browser scanning skips kernel ranges without first reading and hashing an entire dump. A sequential complete read also verifies the whole-file SHA-256. Ordinary files are size- and SHA-256-verified before opening. SQLite and ImHex receive disposable verified copies outside the case, removed when their consumer closes. The output list and case report expose recorded hashes. Damaged or missing requested bytes fail closed.

The desktop loads extracted-file listings and prepares external viewers on background workers. Rendering uses the loaded listing without reading SQLite, traversing directories or reparsing output JSON. Changing the selected run or its status refreshes the listing; Refresh files also reloads availability after filesystem changes.

Evidence images remain external references with import-time SHA-256 fingerprints and explicit integrity verification. Copying a case does not copy its acquisition files. Close the application before copying the whole case directory so SQLite checkpoints its log. Keep the database and `objects` directory together.

Reopening marks queued or running analyses interrupted and does not restart them. Queue clearing dismisses entries while preserving observations, history and binary provenance. Reports and CSV exports run on background workers. Exports cannot replace the database, its sidecars, managed binary storage, captured analysis output or registered evidence.

The external CLI still creates complete staging files before publication, so staging space is required and Volatility's extraction time remains. Chunked outputs above 32 GiB are rejected with captures retained, using the same bound on writing and reading. Ordinary DumpFiles outputs have no manifest limit. See [the design rationale](authoritative-case-design.md) for ownership and validation requirements.
