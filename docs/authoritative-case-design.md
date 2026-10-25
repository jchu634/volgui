# Authoritative case storage

## Problem and grounding

The old case JSON owned runs, evidence and annotations while SQLite owned results. A completed scan could be committed to one store before the other. Each execution repeated result payloads and retained independent binary dumps. Browser recovery and hex inspection depended on physical paths. These paths must remain usable as logical addresses while storage changes.

The user explicitly authorized a breaking pre-alpha format with no legacy migration. Existing case directories must remain untouched when rejected. The prior storage documentation justified raw outputs for provenance and immutable run imports for bookmark identity. Both requirements carry forward. Source history and local documentation were consulted; no external issue, chat, observability or analytics connectors were available for historical rationale. The referenced `how` and `arena` skills were not installed, so grounding was traced directly and two independent design runners were used.

## Usage

```rust,ignore
let case = Case::create_named(parent, "Investigation")?;
let case = Case::open(parent.join("Investigation/case.sqlite"))?;
// Execution workers produce independent captures; publication archives the bytes.
ObjectStore::at(&case.directory).capture_run(&run.id, cancel)?;
ResultStore::at(&case.directory).insert_cancellable(&run, &table, cancel)?;
let mut bytes = extracted_files::open_artifact(&logical_output_path)?;
bytes.seek(SeekFrom::Start(original_dump_offset))?;
```

## Shape and synthesis

Candidate A proposed normalized entities, immutable observations and a deep case API. Candidate B proposed an immutable observation spine with derived entity views. The implementation combines A's explicit entity identities with B's exact observation sharing and immutable source payloads. SQL projections retain the existing display-facing record interface while replacing its persistence.

SQLite v2 owns case metadata, evidence fingerprints, run history, bookmarks, observations, entity enrichment, binary object manifests and output provenance. In-memory case state is a disposable snapshot loaded from SQLite. There is no case JSON manifest or JSON-to-SQLite migration.

Binary storage uses SHA-256 for whole-file and 4 KiB chunk identities. Chunks are compressed into an append-only pack, avoiding millions of tiny filesystem files. SQLite stores compressed ordered chunk manifests and pack offsets. Logical outputs retain distinct run/name provenance even when their content hashes match. Physical acquisition addresses never authorize byte deduplication.

Ingestion writes and synchronizes pack bytes before publishing references in SQLite. A rolled-back operation can leave an unreachable pack tail; it cannot publish missing bytes. Chunk reuse verifies stored bytes against incoming bytes. Random reads verify each chunk. Materialization and export additionally verify the whole-file digest. Corruption fails closed. Complete kernel and user mappings are retained.

Workers retain independent capture directories. Published files are removed only after catalog commit and a metadata stability check. Unpublished captures remain available after errors. The existing exclusive case lock and SQLite WAL coordinate concurrent workers.

Canonical subjects and immutable observations have different identities. Process identity is evidence-scoped and must account for object address or creation time; ambiguous PID matches remain separate. File paths and URLs alone cannot establish forensic identity. Conflicting facts retain their sources. Grouped browsing can coalesce duplicate observations; per-run row addresses remain available for provenance and bookmarks.

Materialized files are disposable leases for SQLite inspection and external viewers. They are not authoritative. The case database and managed object directory are protected from export replacement.

## Alternatives and tradeoffs

- Whole-file-only deduplication preserves a simpler reader but misses repeated kernel pages across different process dumps.
- One file per chunk causes excessive filesystem overhead. An append-only pack trades garbage tail space after interrupted writes for fewer filesystem objects and a smaller public reader API.
- Putting all binary payloads into SQLite couples multi-gigabyte payload writes to the query database. The managed pack keeps SQLite authoritative over identities and references while separating bulk bytes.
- No old-case conversion is provided. Rejecting incompatible formats is explicit and does not delete their data.
- Capturing the external CLI's full files before archiving still requires temporary space. Avoiding that peak requires a different engine-output protocol.

## Validation

Required checks cover cross-file chunk sharing, exact reconstruction and SHA-256 identity, corrupt reused chunks, random offset reads, evidence separation, incremental entity facts, conflicting observations, cancelled transactions, reopen, bookmarks, browser and SQLite parsing, export protection and case-folder validation. Test claims belong in the completed work report, not this design sketch.
