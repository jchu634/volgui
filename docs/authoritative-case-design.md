# Authoritative case storage

## Usage

```rust,ignore
let case = Case::create_named(parent, "Investigation")?;
let case = Case::open(parent.join("Investigation/case.sqlite"))?;
ObjectStore::at(&case.directory).capture_run(&run.id, cancel)?;
ResultStore::at(&case.directory).insert_cancellable(&run, &table, cancel)?;
let mut bytes = extracted_files::open_artifact(&logical_output_path)?;
bytes.seek(SeekFrom::Start(original_dump_offset))?;
```

## Ownership

SQLite v4 owns case metadata, evidence fingerprints, run history, bookmarks,
immutable observations, entity facts and output provenance. The in-memory case
is a disposable metadata snapshot. Most binary outputs use the managed chunk
store. Files recovered by DumpFiles use ordinary files in `objects/blobs`.

The storage module owns this policy and exposes the same capture/open/materialize
API to callers. SQLite records complete output SHA-256 hashes and sizes for both
forms. Chunked objects additionally have ordered, compressed manifests containing
chunk hashes and pack locations. Run/name provenance remains separate from byte
identity. Formats before v4 are rejected without modifying their data.

Canonical subjects and immutable observations remain distinct. Process identity
is evidence-scoped and accounts for object address or creation time; ambiguous
PID matches stay separate. Paths and URLs alone do not establish forensic
identity. Conflicting facts retain their sources, and grouped browsing retains
stable per-run row addresses for provenance and bookmarks.

## Publication and reads

Workers own independent CLI capture directories. Publication buffers reads and
pack writes outside a SQLite transaction. One cancellable filesystem lock
serializes archivers for a case. A local digest-to-location cache verifies a
reused stored chunk once per publication and avoids repeated SQL lookups for
shared pages. Ordinary recovered files are copied and hashed independently.

Publication synchronizes all output bytes, then commits the chunk catalog,
object manifests and output references together. Run/name identities remain
immutable. Failed or cancelled publication truncates its pack tail and removes
unpublished ordinary files. Staging cleanup removes only unchanged files after
references commit. Retrying an ordinary file keeps its original catalogued blob.
A crash may leave unreferenced bytes; garbage collection is not included.

Chunk readers authenticate the manifest before opening and each requested chunk
before returning bytes. Manifest entries contain pack locations, so readers
need no SQLite connection while scanning. Buffered seeks reuse nearby encoded
bytes. A sequential read verifies the whole-file hash at its final byte. Random
reads verify their pages; they do not certify unread pages. Ordinary files verify
the complete hash before opening. SQLite previews and external viewers receive
disposable verified copies outside the case. Exports protect the case database,
managed output directory, staging files and registered evidence.

## Storage design decision

The caller continues to use `capture_run`, `open` and `materialize`. The internal
shapes are `PendingBlob` for ordinary recovered files, `PendingPack` for rollback
of uncommitted appends, and `ObjectReader` for authenticated manifest reads.

Two designs were compared. Restoring hash-only manifests and looking up every
page in SQLite would retain the original format but repeat database work during
browser scanning. Storing authenticated pack locations in the manifest keeps
that lookup inside publication. The latter was chosen. It increases the raw
manifest entry from 32 to 48 bytes, compressed on disk, while allowing scans and
hex paging to read directly from the pack. Both reader and writer enforce the
same 32 GiB object bound.

Whole-file deduplication alone was rejected because different process dumps
contain many identical pages in different orders. Chunk storage preserves the
complete dumps, including kernel data, while letting browser scans read only
user-space pages. DumpFiles outputs stay ordinary files because the intended
exception permits duplicating recovered bytes outside those dumps.

## Desktop responsiveness

Case snapshots save through an ordered background worker. Analysis workers wait
for a metadata checkpoint before executing; SQLite lock waits never block the UI.
Finding imports and output publication retain cancellation-aware writer waits.

The file details panel renders an asynchronously loaded listing. A directory or
run-status change invalidates it, and an epoch rejects stale responses. Refresh
files reloads filesystem availability. Rendering never traverses output folders,
opens SQLite, reparses `stdout.json` or searches PATH for ImHex. Dump completion
and external viewer preparation also run off-thread.

## Validation

Storage tests cover shared pages and complete objects across concurrent runs,
ordinary duplicate files, random offsets, full hashes, manifest corruption,
requested-page corruption, corrupt-chunk reuse, empty files, immutable output
identities, cancellable pack locks, failed-publication rollback, staging retention,
reopen, read-only SQLite inspection and export protection. Browser tests read
archived dumps and verify findings, byte offsets and completed dump reuse.
Listing tests cover archived, missing and blocked outputs plus refresh after an
integrity failure. Queue tests hold a SQLite writer during desktop transitions,
reads, cancellation and output publication. Older case formats are rejected
without changing their version or metadata.

An opt-in synthetic benchmark compares four 64 MiB dumps with shared,
incompressible kernel pages and 2 MiB of distinct user pages per PID. On the
validation machine, ordinary storage would retain 256 MiB; the chunk pack and
case catalog retained 74.5 MiB. Full-file hashing followed by user-range reads
took 153 ms, versus 49 ms for verified chunk range reads. Archival took 1.80 s.
These measurements cover storage and reads, not Volatility dump generation or
end-to-end browser analysis. They are a reproducible sample, not a performance
guarantee.
