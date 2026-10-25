use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use volgui::{
    case::{Case, CaseSnapshot, Evidence, QueueClearScope, Run, RunStatus, now},
    database,
    object_store::ObjectStore,
    results::ResultStore,
    volatility::{Outcome, Table},
};

fn fixture() -> (tempfile::TempDir, Case) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Contention").unwrap();
    let image = temp.path().join("memory.raw");
    fs::write(&image, b"queue contention fixture").unwrap();
    case.add_evidence(Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap())
        .unwrap();
    (temp, case)
}

fn run(case: &Case) -> Run {
    Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: case.document.evidence[0].id.clone(),
        plugin: "windows.pslist.PsList".into(),
        arguments: vec![],
        command: vec!["fixture".into()],
        engine_version: "fixture".into(),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Queued,
        exit_code: None,
        row_count: 0,
        message: String::new(),
    }
}

#[test]
fn synchronous_case_save_waits_for_import_writer_while_wal_reads_continue() {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(temp.path(), "Contention").unwrap();
    let writer = database::connect(temp.path()).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = case.save();
        tx.send(result).unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    assert_eq!(ResultStore::at(temp.path()).count("missing").unwrap(), 0);
    writer.execute_batch("COMMIT").unwrap();
    rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    worker.join().unwrap();
    println!(
        "Synchronous save waited {:?} behind the import writer",
        started.elapsed()
    );
}

#[test]
fn desktop_queue_transitions_and_reads_do_not_wait_for_an_import_writer() {
    let (_temp, mut case) = fixture();
    let first = run(&case);
    let second = run(&case);
    let third = run(&case);
    case.queue_batch(vec![first.clone(), second.clone()])
        .unwrap();
    let store = ResultStore::at(&case.directory);
    store
        .insert(
            &first,
            &Table::parse(r#"[{"PID":1,"ImageFileName":"fixture.exe"}]"#).unwrap(),
        )
        .unwrap();
    for run in &mut case.document.runs {
        run.status = RunStatus::Running;
    }
    case.save().unwrap();
    case.enable_background_saves().unwrap();

    // A different job is doing a long import. None of the UI operations below
    // may need its write lock, including finishing and replacing a queue slot.
    let writer = database::connect(&case.directory).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (tx, rx) = mpsc::channel();
    let first_id = first.id.clone();
    let second_id = second.id.clone();
    let started = Instant::now();
    let worker = thread::spawn(move || {
        case.finish_recorded(
            &first_id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                table: None,
                message: "done".into(),
            },
        )
        .unwrap();
        case.queue(third).unwrap();
        case.document.runs[1].status = RunStatus::Cancelled;
        case.document.runs[2].status = RunStatus::Running;
        case.save().unwrap();
        case.annotate(&first_id, 0, true, "saved during import".into())
            .unwrap();
        assert_eq!(case.clear_queue(QueueClearScope::Finished).unwrap(), 2);
        assert!(case.has_unsaved_changes());
        let checkpoint = case.save_checkpoint().unwrap();
        tx.send((case, checkpoint)).unwrap();
    });
    let response = rx.recv_timeout(Duration::from_secs(1));
    // Release even on regression, so a failed test cannot leave its worker stuck.
    if response.is_err() {
        writer.execute_batch("ROLLBACK").unwrap();
        worker.join().unwrap();
        panic!("Desktop queue actions blocked on the import writer");
    }
    let (mut case, checkpoint) = response.unwrap();
    println!(
        "Desktop queue actions returned in {:?} while the import writer was still locked",
        started.elapsed()
    );
    assert_eq!(store.count(&first.id).unwrap(), 1);
    assert_eq!(store.table(&first.id).unwrap().rows[0].text("PID"), "1");
    let (saved_tx, saved_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        saved_tx
            .send(checkpoint.wait(&AtomicBool::new(false)))
            .unwrap();
    });
    assert!(saved_rx.recv_timeout(Duration::from_millis(150)).is_err());
    writer.execute_batch("COMMIT").unwrap();
    saved_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    while let Some(result) = case.poll_save() {
        result.unwrap();
    }
    assert!(!case.has_unsaved_changes());
    let saved = CaseSnapshot::load(&case.directory).unwrap();
    assert_eq!(saved.runs.len(), 3);
    assert_eq!(saved.runs[0].status, RunStatus::Completed);
    assert_eq!(saved.runs[0].row_count, 1);
    assert_eq!(saved.runs[1].status, RunStatus::Cancelled);
    assert_eq!(saved.runs[2].status, RunStatus::Running);
    assert!(saved.cleared_queue_runs.contains(&first.id));
    assert!(saved.cleared_queue_runs.contains(&second_id));
    assert_eq!(saved.annotations[0].note, "saved during import");
    waiter.join().unwrap();
    worker.join().unwrap();
}

#[test]
fn save_checkpoints_preserve_failures_and_allow_retrying_the_latest_snapshot() {
    let (_temp, mut case) = fixture();
    let db = database::connect(&case.directory).unwrap();
    db.execute_batch(
        "CREATE TRIGGER reject_save BEFORE UPDATE ON case_meta
        WHEN NEW.name='reject' BEGIN SELECT RAISE(ABORT,'fixture save failure'); END;",
    )
    .unwrap();
    case.enable_background_saves().unwrap();
    case.document.name = "reject".into();
    case.save().unwrap();
    let failed = case.save_checkpoint().unwrap();
    case.document.name = "retried".into();
    case.save().unwrap();
    let retried = case.save_checkpoint().unwrap();
    assert!(
        failed
            .wait(&AtomicBool::new(false))
            .unwrap_err()
            .contains("fixture save failure")
    );
    // A later save cannot hide the checkpoint's earlier failure or lose edits.
    assert!(case.poll_save().unwrap().is_err());
    assert!(case.has_unsaved_changes());
    retried.wait(&AtomicBool::new(false)).unwrap();
    while let Some(result) = case.poll_save() {
        result.unwrap();
    }
    assert!(!case.has_unsaved_changes());
    assert_eq!(CaseSnapshot::load(&case.directory).unwrap().name, "retried");
}

#[test]
fn waiting_for_run_metadata_is_cancellable_and_shutdown_drains_saves_under_the_case_lock() {
    let (_temp, mut case) = fixture();
    case.enable_background_saves().unwrap();
    let directory = case.directory.clone();
    let writer = database::connect(&directory).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    case.document.name = "saved before close".into();
    case.save().unwrap();
    let checkpoint = case.save_checkpoint().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        cancelled_tx.send(checkpoint.wait(&worker_cancel)).unwrap();
    });
    assert!(
        cancelled_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
    cancel.store(true, Ordering::Relaxed);
    assert!(
        cancelled_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err()
            .contains("cancelled")
    );
    waiter.join().unwrap();
    let (tx, rx) = mpsc::channel();
    let closer = thread::spawn(move || {
        drop(case);
        tx.send(()).unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
    assert!(
        Case::open(&directory)
            .err()
            .unwrap()
            .contains("already open")
    );
    writer.execute_batch("COMMIT").unwrap();
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    closer.join().unwrap();
    let reopened = Case::open(&directory).unwrap();
    assert_eq!(reopened.document.name, "saved before close");
}

#[test]
fn output_publication_waits_for_imports_and_can_be_cancelled_without_losing_captures() {
    let (_temp, mut case) = fixture();
    let run = run(&case);
    case.queue(run.clone()).unwrap();
    let directory = case.run_dir(&run.id);
    fs::create_dir_all(&directory).unwrap();
    let output = directory.join("output.bin");
    fs::write(&output, b"retained capture").unwrap();
    let writer = database::connect(&case.directory).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let store = ObjectStore::at(&case.directory);
    let run_id = run.id.clone();
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        tx.send(store.capture_run(&run_id, &worker_cancel)).unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
    cancel.store(true, Ordering::Relaxed);
    let result = rx.recv_timeout(Duration::from_secs(1));
    writer.execute_batch("COMMIT").unwrap();
    assert!(result.unwrap().unwrap_err().contains("cancelled"));
    worker.join().unwrap();
    assert!(output.is_file());
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM analysis_outputs", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    assert!(!output.is_file());
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM analysis_outputs", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
