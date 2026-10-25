# Concurrent analysis queue

## Usage

Settings > Maximum simultaneous jobs > Save job limit controls all queued analyses,
including file extraction and native analyses. The default is two. Saving a higher
limit fills available slots immediately. Saving a lower limit leaves active jobs
running and waits until the active count falls below the new limit.

The queue runner calls
`analyses::next_queued_run(&case.document.runs, settings.max_concurrent_jobs)`
until no job can start. Cancelling a job looks up its run ID in the active map.
Finishing a job removes only that entry and updates the UI snapshot. An ordered
background save worker persists desktop snapshots without blocking the UI.

## Shape

`Settings::max_concurrent_jobs: NonZeroUsize` persists the global limit. Existing
settings files receive the default through Serde. The settings dialog validates
and saves this independently of engine discovery, so it works during analysis.

`Workspace::running: HashMap<String, Busy>` owns each active job's cancellation
token. The existing `busy: Option<Busy>` remains for exclusive work such as engine
validation, evidence hashing and opening cases. Case switching and exclusive work
check both kinds of activity. Dropping a job or quitting cancels its worker.

`next_queued_run(runs: &[Run], limit: NonZeroUsize) -> Option<usize>` owns capacity,
queue order and browser parsing barriers. Each worker keeps its own command,
process tree, output directory and run ID. Native browser parsing starts after
earlier jobs finish and blocks later jobs while it reads their outputs. Automatic
browser recovery preparation waits until the queue and all active workers finish.

Result imports acquire an immediate SQLite write transaction before reading.
Competing imports wait in short intervals and check their cancellation tokens.
This avoids failed read-to-write upgrades when two workers finish together and
allows large imports to finish without a fixed lock timeout failing another job.

## Desktop persistence under concurrent imports

The authoritative-storage rewrite put run metadata and results in the same SQLite
database. Although WAL permits readers during imports, a UI-thread `Case::save`
still waits for the import's write lock. Queue completion and slot refill both
called it, making the entire window wait for another job's import or the 30-second
busy timeout.

Desktop case ownership now opts into background saves. CLI and example callers
keep synchronous persistence. The caller's flow is:

```rust,ignore
case.enable_background_saves()?;
case.queue_batch(runs)?; // Accept an ordered snapshot without waiting for SQLite.
case.save()?;
let checkpoint = case.save_checkpoint()?;
// On the analysis worker, before executing or publishing outputs:
checkpoint.wait(cancel)?;
// On each UI poll, surface errors and pause the queue:
while let Some(result) = case.poll_save() { /* handle result */ }
```

`CaseSnapshot::persist(transaction)` owns the SQL snapshot writes. `BackgroundSaves`
owns the ordered channel, save revisions and worker lifetime. Consecutive pending
snapshots coalesce because each contains all UI edits. Durability checkpoints
prevent coalescing across a worker's required metadata save. Checkpoint waits are
cancellable and happen only on analysis workers. Imports and binary publication
retain their existing transactions and WAL isolation.

Background snapshot saves, finding imports and output publication share
`database::write_transaction(db, cancel)`. It acquires an immediate transaction
before any transactional reads and checks cancellation between short lock waits.
Long imports do not fail another writer at the connection's default busy timeout.

Failed writes report through the UI poll and their checkpoint; a later success
does not hide an earlier checkpoint failure. The latest in-memory snapshot remains
available to the existing retry-save action. Case switching waits for successful
save acknowledgements. Dropping a case drains accepted saves before releasing its
exclusive directory lock.

Shortening imports into several commits was also considered. It would require
hiding partial findings, preserving rollback and rebuilding entity associations
across batches, while still leaving UI writes exposed to contention. Moving
snapshot saves off-thread preserves atomic imports and removes that UI dependency.

## Design decision

Two shapes were considered. A dedicated worker-pool service could hide scheduling,
but would need to coordinate persisted run transitions with the UI's case owner.
The chosen design keeps that ownership and extends its event loop to fill slots.
The selection function hides capacity and dependency policy behind one call, while
the active map keeps process ownership and cancellation in the existing workspace.

Browser parsing uses a conservative queue barrier rather than persisted dependency
graphs. It can delay later independent jobs, but preserves the existing ordering
contract without changing the case format. A slot remains occupied through result
import and submission of the outcome snapshot. Its replacement waits for its own
metadata checkpoint before executing, so the configured cap still bounds analysis
and import workers.

## Validation

Scheduler tests cover filling slots, out-of-order completion, cancellation,
increasing and decreasing the limit, and browser barriers. A test CLI holds two
distinct processes open at once, cancels one, refills its slot, and checks that
the other process and its outputs survive. SQLite tests hold a writer lock while
competing imports wait, cancel one waiter, then verify the others persist.

`tests/queue_responsiveness.rs` first reproduces a synchronous snapshot save
waiting behind an import writer while WAL reads continue. Desktop tests hold the
same writer lock and require completion, queueing, cancellation, bookmarking and
queue clearing to return before releasing it. They verify durable final state,
checkpoint failure and retry ordering, cancellable metadata waits and lock
ownership while shutdown drains pending saves. Output publication is cancelled
while another writer holds the database, then retried without losing its capture.
