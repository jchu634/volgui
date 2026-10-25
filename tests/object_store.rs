use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
};
use volgui::{
    case::{Case, Evidence, Run, RunStatus, now},
    object_store::{self, CHUNK_SIZE, ObjectStore},
};

fn fixture() -> (tempfile::TempDir, Case, Run) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create_named(temp.path(), "Storage").unwrap();
    let source = temp.path().join("image.bin");
    fs::write(&source, b"original acquisition").unwrap();
    case.add_evidence(Evidence::inspect(&source, &AtomicBool::new(false), |_, _| {}).unwrap())
        .unwrap();
    let run = Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: case.document.evidence[0].id.clone(),
        plugin: "windows.memmap.Memmap".into(),
        arguments: vec![],
        command: vec!["fixture".into()],
        engine_version: "fixture-v1".into(),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Queued,
        exit_code: None,
        row_count: 0,
        message: String::new(),
    };
    case.queue(run.clone()).unwrap();
    fs::create_dir_all(case.run_dir(&run.id)).unwrap();
    (temp, case, run)
}

#[test]
fn different_dumps_share_pages_but_reconstruct_complete_original_bytes_and_hashes() {
    let (temp, case, run) = fixture();
    let a = vec![0x41; CHUNK_SIZE];
    let b = vec![0x42; CHUNK_SIZE];
    let first = [a.clone(), b.clone(), a.clone(), b"tail".to_vec()].concat();
    let second = [b, a.clone(), a, b"tail".to_vec()].concat();
    let p = case.run_dir(&run.id).join("pid.1.dmp");
    let q = case.run_dir(&run.id).join("pid.2.dmp");
    fs::write(&p, &first).unwrap();
    fs::write(&q, &second).unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    assert!(!p.exists());
    assert!(!q.exists());
    let db = volgui::database::connect(&case.directory).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM binary_chunks", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    for (path, expected) in [(&p, &first), (&q, &second)] {
        let digest = format!("{:x}", Sha256::digest(expected));
        assert_eq!(object_store::stored_hash(path).unwrap().unwrap(), digest);
        let mut reader = object_store::open(path).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes, expected);
        reader.seek(SeekFrom::Start(CHUNK_SIZE as u64 - 2)).unwrap();
        let mut boundary = [0; 8];
        reader.read_exact(&mut boundary).unwrap();
        assert_eq!(&boundary, &expected[CHUNK_SIZE - 2..CHUNK_SIZE + 6]);
        let materialized = object_store::materialize(path).unwrap();
        assert_eq!(fs::read(materialized.path()).unwrap(), *expected);
    }
    let mut reader = object_store::open(&p).unwrap();
    case.document
        .export_reader(
            &case.directory,
            &temp.path().join("export.dmp"),
            &mut reader,
        )
        .unwrap();
    assert_eq!(fs::read(temp.path().join("export.dmp")).unwrap(), first);
    let logical = object_store::list(&case.run_dir(&run.id)).unwrap();
    assert_eq!(logical.len(), 2);
}

#[test]
fn duplicate_files_retain_distinct_provenance_without_duplicate_objects() {
    let (_temp, case, run) = fixture();
    let p = case.run_dir(&run.id).join("one.dat");
    let q = case.run_dir(&run.id).join("two.dat");
    fs::write(&p, b"identical bytes").unwrap();
    fs::write(&q, b"identical bytes").unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM binary_objects", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM analysis_outputs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        object_store::stored_hash(&p).unwrap(),
        object_store::stored_hash(&q).unwrap()
    );
}

#[test]
fn corruption_is_rejected_on_read_and_reuse_without_removing_new_capture() {
    let (_temp, case, run) = fixture();
    let p = case.run_dir(&run.id).join("one.dat");
    fs::write(&p, vec![0x61; CHUNK_SIZE]).unwrap();
    let store = ObjectStore::at(&case.directory);
    store.capture_run(&run.id, &AtomicBool::new(false)).unwrap();
    let mut pack = fs::OpenOptions::new()
        .write(true)
        .open(case.directory.join("objects/chunks.pack"))
        .unwrap();
    pack.write_all(&[0xff; 8]).unwrap();
    drop(pack);
    let mut bytes = Vec::new();
    assert!(
        object_store::open(&p)
            .unwrap()
            .read_to_end(&mut bytes)
            .is_err()
    );
    assert!(bytes.is_empty());
    let q = case.run_dir(&run.id).join("two.dat");
    fs::write(&q, vec![0x61; CHUNK_SIZE]).unwrap();
    assert!(store.capture_run(&run.id, &AtomicBool::new(false)).is_err());
    assert!(q.is_file());
    assert!(object_store::stored_hash(&q).unwrap().is_none());
}

#[test]
fn cancelled_archive_publishes_nothing_and_preserves_capture() {
    let (_temp, case, run) = fixture();
    let p = case.run_dir(&run.id).join("one.dat");
    fs::write(&p, b"captured").unwrap();
    assert!(
        ObjectStore::at(&case.directory)
            .capture_run(&run.id, &AtomicBool::new(true))
            .is_err()
    );
    assert!(p.exists());
    assert!(object_store::stored_hash(&p).unwrap().is_none());
}

#[test]
fn empty_output_and_tampered_manifest_are_checked() {
    let (_temp, case, run) = fixture();
    let p = case.run_dir(&run.id).join("empty.dat");
    fs::write(&p, b"").unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    let mut bytes = Vec::new();
    object_store::open(&p)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.is_empty());
    let db = volgui::database::connect(&case.directory).unwrap();
    db.execute("UPDATE binary_objects SET manifest_sha256='tampered'", [])
        .unwrap();
    assert!(object_store::open(&p).is_err());
}

#[test]
fn exports_cannot_replace_object_store_or_database() {
    let (_temp, case, _) = fixture();
    fs::create_dir_all(case.directory.join("objects")).unwrap();
    for target in [
        case.directory.join("case.sqlite"),
        case.directory.join("objects/chunks.pack"),
    ] {
        assert!(
            case.document
                .export(&case.directory, &target, b"bad")
                .is_err()
        );
    }
}

#[test]
fn transient_failures_and_missing_diagnostics_do_not_permanently_block_outputs() {
    let (_temp, case, run) = fixture();
    let path = case.run_dir(&run.id).join("file.dat");
    fs::write(&path, b"healthy output").unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    volgui::extracted_files::block_artifact(&path, "database is locked; sharing violation")
        .unwrap();
    volgui::extracted_files::ensure_openable(&path).unwrap();
    let missing = case.run_dir(&run.id).join("stderr.log");
    assert!(volgui::extracted_files::open_artifact(&missing).is_err());
    assert!(
        !case
            .run_dir(&run.id)
            .join("stderr.log.volgui-blocked")
            .exists()
    );
    let db = volgui::database::connect(&case.directory).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM analysis_outputs WHERE blocked_reason IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn sqlite_preview_materializes_verified_content_and_catalog_survives_reopen() {
    let (temp, case, run) = fixture();
    let source = temp.path().join("history.sqlite");
    let sqlite = rusqlite::Connection::open(&source).unwrap();
    sqlite
        .execute_batch(
            "CREATE TABLE history(url TEXT);INSERT INTO history VALUES('https://example.test/');",
        )
        .unwrap();
    drop(sqlite);
    let output = case.run_dir(&run.id).join("History.dat");
    fs::copy(&source, &output).unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    let directory = case.directory.clone();
    drop(case);
    let reopened = Case::open(&directory).unwrap();
    assert!(!reopened.directory.join("case.volgui.json").exists());
    let page = volgui::file_content::database_page(&output, None, 0).unwrap();
    assert_eq!(page.path, output);
    assert_eq!(page.rows[0][0], "https://example.test/");
    let metadata = object_store::output_metadata(&reopened.run_dir(&run.id)).unwrap();
    assert!(metadata[&output].sha256.is_some());
    assert!(metadata[&output].blocked_reason.is_none());
}

#[test]
fn cli_completion_archives_failed_output_without_publishing_successful_findings() {
    let (_temp, mut case, run) = fixture();
    let path = case.run_dir(&run.id).join("partial.dmp");
    fs::write(&path, b"partial recovered content").unwrap();
    case.finish(
        &run.id,
        &volgui::volatility::Outcome {
            status: RunStatus::Failed,
            exit_code: Some(1),
            message: "engine failure".into(),
            table: None,
        },
    )
    .unwrap();
    assert!(!path.is_file());
    assert!(object_store::stored_hash(&path).unwrap().is_some());
    assert_eq!(case.document.runs[0].status, RunStatus::Failed);
    assert_eq!(case.document.runs[0].row_count, 0);
}
