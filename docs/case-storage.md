# Case storage

Choose a parent location and case name to create a new folder. Existing folders are never replaced. Open a case folder or its `case.sqlite` database.

SQLite format v4 owns metadata, evidence fingerprints, analysis history, bookmarks, observations, entity facts and output references. Older formats are rejected without modification. Repeated findings share immutable payloads while retaining each run and source row. Conflicting facts retain provenance; ambiguous identities remain separate.

## Recovered outputs

Process dumps and most analysis outputs share compressed, SHA-256-addressed 4 KiB chunks. DumpFiles outputs remain independent ordinary files. Every output retains its size and complete SHA-256; exported files are standalone copies.

Publication synchronizes bytes before committing references. Cancellation rolls back unpublished data and preserves staging captures. A crash can leave unreferenced bytes; automatic garbage collection is not implemented. The CLI needs staging space for complete outputs. Chunked outputs are limited to 32 GiB; ordinary DumpFiles outputs have no manifest limit.

Readers verify manifests and requested chunks. Complete sequential reads also verify the whole-file hash; ordinary files are fully verified before opening. SQLite previews and external viewers receive disposable verified copies. Missing or damaged requested bytes fail closed. Listings and viewer preparation run on background workers.

## Copying and reopening

Close the app before copying the entire case folder so SQLite checkpoints its log. Keep the database and managed outputs together. Acquisition images remain external and must be copied separately. Their import-time fingerprints support explicit integrity checks.

Reopening marks queued/running jobs interrupted without restarting them. Clearing the queue preserves findings, history and binary provenance. Exports cannot overwrite case data or registered evidence.

## Rescan a case

Finish or cancel active and queued jobs, then choose **New analysis > Advanced > Rescan case**. This reruns each distinct previous scan configuration across all evidence, including dismissed and unsuccessful jobs, using the current app and engine.

Rescanning replaces findings, history, notes and bookmarks after saving a backup of the previous database and managed outputs. Open the backup as a case to inspect earlier results. Evidence remains external. Preparation, backup and cancellation failures preserve current results; existing chunks remain available for reuse.

See [storage architecture](architecture/authoritative-case-design.md) for publication and integrity details.
