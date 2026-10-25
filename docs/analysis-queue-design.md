# Concurrent analysis queue

## Usage

Settings > Maximum simultaneous jobs > Save job limit controls all queued analyses,
including file extraction and native analyses. The default is two. Saving a higher
limit fills available slots immediately. Saving a lower limit leaves active jobs
running and waits until the active count falls below the new limit.

The queue runner calls
`analyses::next_queued_run(&case.document.runs, settings.max_concurrent_jobs)`
until no job can start. Cancelling a job looks up its run ID in the active map.
Finishing a job removes only that entry and persists its outcome on the UI thread.

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

## Design decision

Two shapes were considered. A dedicated worker-pool service could hide scheduling,
but would need to coordinate persisted run transitions with the UI's case owner.
The chosen design keeps that ownership and extends its event loop to fill slots.
The selection function hides capacity and dependency policy behind one call, while
the active map keeps process ownership and cancellation in the existing workspace.

Browser parsing uses a conservative queue barrier rather than persisted dependency
graphs. It can delay later independent jobs, but preserves the existing ordering
contract without changing the case format. A slot remains occupied through result
import and outcome persistence, so the configured cap covers the full job lifetime.

## Validation

Scheduler tests cover filling slots, out-of-order completion, cancellation,
increasing and decreasing the limit, and browser barriers. A test CLI holds two
distinct processes open at once, cancels one, refills its slot, and checks that
the other process and its outputs survive. SQLite tests hold a writer lock while
competing imports wait, cancel one waiter, then verify the others persist.
