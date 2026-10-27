# Concurrent analysis queue

Settings controls the global job limit, two by default. Raising it fills available slots; lowering it lets active jobs finish before starting more.

`next_queued_run` owns capacity, queue order and parser barriers. `Workspace::running` maps run IDs to cancellation tokens. Each worker owns its process tree, capture and outputs. Exclusive operations check both active jobs and the separate workspace busy state. Quitting cancels workers.

Recovery parsers wait for preceding work and block later jobs while consuming outputs. Deferred recovery resolves prerequisites before execution. A slot remains occupied through result import and outcome submission.

## Persistence

Desktop snapshots save through an ordered background worker; CLI callers save synchronously. Pending snapshots can coalesce, but durability checkpoints preserve metadata required by analysis workers. Workers wait for checkpoints with cancellation before executing or publishing.

Snapshot saves, imports and output publication acquire immediate SQLite write transactions before transactional reads. Short cancellable lock waits avoid read-to-write upgrade failures and keep contention off the UI thread. Imports remain atomic.

Save failures reach both the UI and affected checkpoint. Later success does not hide an earlier failure. The latest snapshot remains available for retry. Case switching waits for save acknowledgements; closing drains accepted saves before releasing the case lock.

Keeping scheduling in the workspace preserves case ownership and cancellation. Conservative parser barriers can delay independent jobs but avoid a persisted dependency graph.

## Validation

Tests cover slot refill, out-of-order completion, limit changes, process cancellation and recovery barriers. Writer-lock tests check UI responsiveness, cancellable waits, checkpoint failure/retry ordering, durable final state and shutdown lock ownership.
