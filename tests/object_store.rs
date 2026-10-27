use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
};
use volgui::{
    case::{Case, Evidence, Run, RunStatus, now},
    object_store::{self, ObjectStore},
};

fn fixture() -> (tempfile::TempDir, Case, Run) {
    fixture_with_plugin("windows.memmap.Memmap")
}

fn fixture_with_plugin(plugin: &str) -> (tempfile::TempDir, Case, Run) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create_named(temp.path(), "Storage").unwrap();
    let source = temp.path().join("image.bin");
    fs::write(&source, b"original acquisition").unwrap();
    case.add_evidence(Evidence::inspect(&source, &AtomicBool::new(false), |_, _| {}).unwrap())
        .unwrap();
    let run = Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: case.document.evidence[0].id.clone(),
        plugin: plugin.into(),
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
fn quarantined_dump_output_preserves_findings_and_healthy_outputs() {
    let (_temp, mut case, run) = fixture_with_plugin(volgui::extracted_files::DUMP_FILES);
    let directory = case.run_dir(&run.id);
    let json = serde_json::json!([
        {"FileObject":4096,"FileName":"runas.exe","File output":"file.quarantined.dat"},
        {"FileObject":8192,"FileName":"healthy.txt","File output":"file.healthy.dat"}
    ])
    .to_string();
    fs::write(directory.join("stdout.json"), &json).unwrap();
    fs::write(directory.join("stderr.log"), "engine completed").unwrap();
    fs::write(directory.join("file.healthy.dat"), b"healthy contents").unwrap();
    // Defender removed the first output between extraction and archiving.
    case.finish(
        &run.id,
        &volgui::volatility::Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(volgui::volatility::Table::parse(&json).unwrap()),
        },
    )
    .unwrap();
    assert_eq!(case.results(&run.id).unwrap().rows.len(), 2);
    let completed = case
        .document
        .runs
        .iter()
        .find(|saved| saved.id == run.id)
        .unwrap();
    assert_eq!(completed.status, RunStatus::Warning);
    assert_eq!(completed.row_count, 2);
    assert!(
        completed
            .message
            .contains("outputs are unavailable or blocked")
    );
    let outputs = object_store::output_metadata(&directory).unwrap();
    assert!(
        outputs[&directory.join("file.quarantined.dat")]
            .blocked_reason
            .is_some()
    );
    assert!(
        outputs[&directory.join("file.healthy.dat")]
            .sha256
            .is_some()
    );
    assert!(
        volgui::extracted_files::open_artifact(&directory.join("file.quarantined.dat")).is_err()
    );
    assert!(volgui::extracted_files::open_artifact(&directory.join("file.healthy.dat")).is_ok());
    let store = volgui::results::ResultStore::at(&case.directory);
    let ids = store
        .query(&volgui::results::Query {
            runs: vec![run.id.clone()],
            ..Default::default()
        })
        .unwrap()
        .ids;
    let rows = store.fetch(&ids).unwrap();
    let recovery =
        volgui::analysis::files::RecoveryIndex::load(&case.directory, &case.document).unwrap();
    assert_eq!(
        recovery.state(&rows[0], false),
        volgui::analysis::files::RecoveryState::Unavailable
    );
    assert_eq!(
        recovery.state(&rows[1], false),
        volgui::analysis::files::RecoveryState::Recovered
    );
}

#[test]
fn dumps_share_pages_and_preserve_exact_bytes_offsets_hashes_and_exports() {
    let (temp, case, run) = fixture();
    let a = vec![0x41; 4096];
    let b = vec![0x42; 4096];
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
    assert_eq!(
        db.query_row("SELECT count(*) FROM analysis_outputs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert!(
        fs::metadata(case.directory.join("objects/chunks.pack"))
            .unwrap()
            .len()
            < 1024
    );
    assert_eq!(
        fs::read_dir(case.directory.join("objects/blobs"))
            .unwrap()
            .count(),
        0
    );
    for (path, expected) in [(&p, &first), (&q, &second)] {
        let digest = format!("{:x}", Sha256::digest(expected));
        assert_eq!(object_store::stored_hash(path).unwrap().unwrap(), digest);
        let mut reader = object_store::open(path).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes, expected);
        reader.seek(SeekFrom::Start(4094)).unwrap();
        let mut boundary = [0; 8];
        reader.read_exact(&mut boundary).unwrap();
        assert_eq!(&boundary, &expected[4096 - 2..4096 + 6]);
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
fn duplicate_files_retain_independent_blobs_and_distinct_provenance() {
    let (_temp, case, run) = fixture_with_plugin("windows.dumpfiles.DumpFiles");
    let p = case.run_dir(&run.id).join("one.dat");
    let q = case.run_dir(&run.id).join("two.dat");
    fs::write(&p, b"identical bytes").unwrap();
    fs::write(&q, b"identical bytes").unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(DISTINCT blob_id) FROM analysis_outputs",
            [],
            |r| { r.get::<_, i64>(0) }
        )
        .unwrap(),
        2
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
    let mut query = db
        .prepare("SELECT blob_id FROM analysis_outputs ORDER BY name")
        .unwrap();
    let blobs: Vec<String> = query
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for id in &blobs {
        assert_eq!(
            fs::read(case.directory.join("objects/blobs").join(id)).unwrap(),
            b"identical bytes"
        );
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM binary_chunks", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn corrupt_blobs_fail_closed_without_affecting_independent_copies() {
    let (_temp, case, run) = fixture_with_plugin("windows.dumpfiles.DumpFiles");
    let p = case.run_dir(&run.id).join("one.dat");
    let original = vec![0x61; 4096];
    fs::write(&p, &original).unwrap();
    let store = ObjectStore::at(&case.directory);
    store.capture_run(&run.id, &AtomicBool::new(false)).unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    let id: String = db
        .query_row("SELECT blob_id FROM analysis_outputs", [], |r| r.get(0))
        .unwrap();
    let mut blob = fs::OpenOptions::new()
        .write(true)
        .open(case.directory.join("objects/blobs").join(id))
        .unwrap();
    blob.write_all(&[0xff; 8]).unwrap();
    drop(blob);
    assert!(
        object_store::open(&p)
            .err()
            .unwrap()
            .contains("SHA-256 mismatch")
    );
    let q = case.run_dir(&run.id).join("two.dat");
    fs::write(&q, &original).unwrap();
    store.capture_run(&run.id, &AtomicBool::new(false)).unwrap();
    let mut bytes = Vec::new();
    object_store::open(&q)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, original);
    assert!(object_store::open(&p).is_err());
    // Retrying an existing run/name cannot change its immutable identity.
    fs::write(&p, b"different content").unwrap();
    assert!(
        store
            .capture_run(&run.id, &AtomicBool::new(false))
            .unwrap_err()
            .contains("immutable")
    );
    assert_eq!(fs::read(&p).unwrap(), b"different content");
    assert_eq!(
        fs::read_dir(case.directory.join("objects/blobs"))
            .unwrap()
            .count(),
        2
    );
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
fn failed_catalog_publication_rolls_back_metadata_and_removes_unpublished_files() {
    let (_temp, case, run) = fixture_with_plugin("windows.dumpfiles.DumpFiles");
    let first = case.run_dir(&run.id).join("first.dat");
    let second = case.run_dir(&run.id).join("second.dat");
    fs::write(&first, b"first capture").unwrap();
    fs::write(&second, b"second capture").unwrap();
    let diagnostic = case.run_dir(&run.id).join("stdout.json");
    fs::write(&diagnostic, b"[]").unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_publication BEFORE INSERT ON analysis_outputs
        WHEN NEW.name='second.dat' BEGIN SELECT RAISE(ABORT,'fixture publication failure'); END;",
    )
    .unwrap();
    assert!(
        ObjectStore::at(&case.directory)
            .capture_run(&run.id, &AtomicBool::new(false))
            .unwrap_err()
            .contains("fixture publication failure")
    );
    assert_eq!(fs::read(&first).unwrap(), b"first capture");
    assert_eq!(fs::read(&second).unwrap(), b"second capture");
    assert_eq!(fs::read(&diagnostic).unwrap(), b"[]");
    assert_eq!(
        fs::read_dir(case.directory.join("objects/blobs"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM analysis_outputs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM binary_chunks", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        fs::metadata(case.directory.join("objects/chunks.pack"))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn identical_analysis_outputs_share_storage_across_concurrent_runs() {
    let (_temp, mut case, run) = fixture();
    let mut other = run.clone();
    other.id = uuid::Uuid::new_v4().to_string();
    case.queue(other.clone()).unwrap();
    fs::create_dir_all(case.run_dir(&other.id)).unwrap();
    let bytes = [vec![0x61; 4096], vec![0x62; 4096]].concat();
    for r in [&run, &other] {
        fs::write(case.run_dir(&r.id).join("pid.dmp"), &bytes).unwrap();
    }
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            ObjectStore::at(&case.directory).capture_run(&run.id, &AtomicBool::new(false))
        });
        let second = scope.spawn(|| {
            ObjectStore::at(&case.directory).capture_run(&other.id, &AtomicBool::new(false))
        });
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    });
    let db = volgui::database::connect(&case.directory).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM binary_chunks", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
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
    for r in [&run, &other] {
        assert_eq!(
            fs::read(
                object_store::materialize(&case.run_dir(&r.id).join("pid.dmp"))
                    .unwrap()
                    .path()
            )
            .unwrap(),
            bytes
        );
    }
}

#[test]
fn chunk_reads_verify_requested_pages_and_reuse_rejects_corruption() {
    let (_temp, case, run) = fixture();
    let path = case.run_dir(&run.id).join("pid.dmp");
    let user = vec![0x61; 4096];
    let kernel = vec![0x62; 4096];
    fs::write(&path, [user.clone(), kernel.clone()].concat()).unwrap();
    let store = ObjectStore::at(&case.directory);
    store.capture_run(&run.id, &AtomicBool::new(false)).unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    let offset: i64 = db
        .query_row(
            "SELECT pack_offset FROM binary_chunks WHERE sha256=?1",
            [Sha256::digest(&kernel).as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let pack_path = case.directory.join("objects/chunks.pack");
    let mut pack = fs::OpenOptions::new().write(true).open(&pack_path).unwrap();
    pack.seek(SeekFrom::Start(offset as u64)).unwrap();
    pack.write_all(&[0xff; 8]).unwrap();
    drop(pack);
    // Browser scanning may read only user pages. Opening does not read excluded kernel bytes.
    let mut reader = object_store::open(&path).unwrap();
    let mut bytes = vec![0; 4096];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, user);
    assert!(reader.read_exact(&mut bytes).is_err());
    assert!(object_store::materialize(&path).is_err());
    let retry = case.run_dir(&run.id).join("another.dmp");
    fs::write(&retry, &kernel).unwrap();
    let before = fs::metadata(&pack_path).unwrap().len();
    assert!(store.capture_run(&run.id, &AtomicBool::new(false)).is_err());
    assert!(retry.exists());
    assert!(object_store::stored_hash(&retry).unwrap().is_none());
    assert_eq!(fs::metadata(&pack_path).unwrap().len(), before);
}

#[test]
fn authenticated_manifests_and_complete_file_hashes_are_checked() {
    let (_temp, case, run) = fixture();
    let path = case.run_dir(&run.id).join("pid.dmp");
    fs::write(&path, [vec![0x61; 4096], vec![0x62; 4096]].concat()).unwrap();
    ObjectStore::at(&case.directory)
        .capture_run(&run.id, &AtomicBool::new(false))
        .unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    let encoded: Vec<u8> = db
        .query_row("SELECT manifest FROM binary_objects", [], |r| r.get(0))
        .unwrap();
    let mut manifest = lz4_flex::decompress_size_prepended(&encoded).unwrap();
    let (a, b) = manifest.split_at_mut(48);
    a.swap_with_slice(b);
    db.execute(
        "UPDATE binary_objects SET manifest=?1",
        [lz4_flex::compress_prepend_size(&manifest)],
    )
    .unwrap();
    assert!(
        object_store::open(&path)
            .err()
            .unwrap()
            .contains("manifest SHA-256 mismatch")
    );
    let recaptured = [vec![0x61; 4096], vec![0x62; 4096]].concat();
    fs::write(&path, &recaptured).unwrap();
    assert!(
        ObjectStore::at(&case.directory)
            .capture_run(&run.id, &AtomicBool::new(false))
            .unwrap_err()
            .contains("manifest mismatch")
    );
    assert_eq!(fs::read(&path).unwrap(), recaptured);
    db.execute(
        "UPDATE binary_objects SET manifest_sha256=?1",
        [format!("{:x}", Sha256::digest(&manifest))],
    )
    .unwrap();
    // Even a consistently rehashed but reordered manifest cannot pass a complete export.
    assert!(
        object_store::materialize(&path)
            .err()
            .unwrap()
            .contains("Complete file SHA-256 mismatch")
    );
    let mut reader = object_store::open(&path).unwrap();
    assert!(
        reader
            .read_exact(&mut vec![0; 8192])
            .unwrap_err()
            .to_string()
            .contains("Complete file SHA-256 mismatch")
    );
}

#[test]
fn waiting_for_pack_writer_can_be_cancelled_without_publication() {
    use std::sync::{Arc, atomic::Ordering};
    let (_temp, case, run) = fixture();
    fs::create_dir_all(case.directory.join("objects")).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(case.directory.join("objects/.writer.lock"))
        .unwrap();
    lock.lock().unwrap();
    let path = case.run_dir(&run.id).join("pid.dmp");
    fs::write(&path, b"pending capture").unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| ObjectStore::at(&case.directory).capture_run(&run.id, &cancel));
        std::thread::sleep(std::time::Duration::from_millis(60));
        cancel.store(true, Ordering::Relaxed);
        assert!(waiter.join().unwrap().unwrap_err().contains("cancelled"));
    });
    assert!(path.exists());
    assert!(object_store::stored_hash(&path).unwrap().is_none());
}

#[test]
fn retrying_an_ordinary_file_keeps_its_existing_blob() {
    let (_temp, case, run) = fixture_with_plugin("windows.dumpfiles.DumpFiles");
    let path = case.run_dir(&run.id).join("file.dat");
    let store = ObjectStore::at(&case.directory);
    for _ in 0..2 {
        fs::write(&path, b"same captured file").unwrap();
        store.capture_run(&run.id, &AtomicBool::new(false)).unwrap();
    }
    assert_eq!(
        fs::read_dir(case.directory.join("objects/blobs"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
#[ignore = "Writes 256 MiB of synthetic process dumps to measure storage and browser-range reads"]
fn benchmark_shared_dumps_and_browser_range_reads() {
    use std::{io::BufWriter, time::Instant};
    let (_temp, mut case, template) = fixture();
    let user_size = 2 * 1024 * 1024;
    let kernel_size = 62 * 1024 * 1024;
    let mut state = 0x3c79ac492ba7b653u64;
    let mut random = |size: usize| -> Vec<u8> {
        (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    };
    let kernel = random(kernel_size);
    let mut sources = Vec::new();
    let mut runs = vec![template.clone()];
    for _ in 1..4 {
        let mut run = template.clone();
        run.id = uuid::Uuid::new_v4().to_string();
        case.queue(run.clone()).unwrap();
        fs::create_dir_all(case.run_dir(&run.id)).unwrap();
        runs.push(run);
    }
    for (pid, run) in runs.iter().enumerate() {
        let user = random(user_size);
        let path = case.run_dir(&run.id).join(format!("pid.{pid}.dmp"));
        let mut output = BufWriter::new(fs::File::create(&path).unwrap());
        output.write_all(&user).unwrap();
        output.write_all(&kernel).unwrap();
        output.flush().unwrap();
        sources.push((path, format!("{:x}", Sha256::digest(&user))));
    }
    let mut buffer = vec![0; 1024 * 1024];
    let baseline_start = Instant::now();
    for (path, expected) in &sources {
        let mut file = fs::File::open(path).unwrap();
        let mut whole = Sha256::new();
        loop {
            let count = file.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            whole.update(&buffer[..count]);
        }
        let _ = whole.finalize();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut user = vec![0; user_size];
        file.read_exact(&mut user).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&user)), *expected);
    }
    let baseline = baseline_start.elapsed();
    let archive_start = Instant::now();
    for run in &runs {
        ObjectStore::at(&case.directory)
            .capture_run(&run.id, &AtomicBool::new(false))
            .unwrap();
    }
    let archive = archive_start.elapsed();
    let read_start = Instant::now();
    for (path, expected) in &sources {
        let mut file = object_store::open(path).unwrap();
        let mut user = vec![0; user_size];
        file.read_exact(&mut user).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&user)), *expected);
    }
    let treatment = read_start.elapsed();
    let pack = fs::metadata(case.directory.join("objects/chunks.pack"))
        .unwrap()
        .len();
    let catalog: u64 = ["case.sqlite", "case.sqlite-wal"]
        .iter()
        .filter_map(|name| fs::metadata(case.directory.join(name)).ok())
        .map(|m| m.len())
        .sum();
    let logical = (4 * (user_size + kernel_size)) as u64;
    println!(
        "logical_bytes={logical} pack_bytes={pack} catalog_bytes={catalog} retained_bytes={}",
        pack + catalog
    );
    println!(
        "baseline_full_hash_then_user_read_ms={:.2} chunk_verified_user_read_ms={:.2} archival_ms={:.2}",
        baseline.as_secs_f64() * 1000.,
        treatment.as_secs_f64() * 1000.,
        archive.as_secs_f64() * 1000.
    );
    assert!(pack + catalog < logical / 2);
}

#[test]
fn old_ordinary_file_storage_format_is_rejected_without_changing_case_data() {
    let (_temp, case, _) = fixture();
    let directory = case.directory.clone();
    let db = volgui::database::connect(&directory).unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
    drop(db);
    drop(case);
    assert!(
        Case::open(&directory)
            .err()
            .unwrap()
            .contains("Unsupported case format")
    );
    let db = rusqlite::Connection::open(directory.join("case.sqlite")).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        db.query_row("SELECT name FROM case_meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "Storage"
    );
}

#[test]
fn empty_output_and_tampered_blob_metadata_are_checked() {
    let (_temp, case, run) = fixture_with_plugin("windows.dumpfiles.DumpFiles");
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
    db.execute("UPDATE analysis_outputs SET sha256='tampered'", [])
        .unwrap();
    assert!(object_store::open(&p).is_err());
}

#[test]
fn exports_cannot_replace_object_store_or_database() {
    let (_temp, case, _) = fixture();
    fs::create_dir_all(case.directory.join("objects/blobs")).unwrap();
    for target in [
        case.directory.join("case.sqlite"),
        case.directory.join("objects/blobs/protected.dat"),
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
fn repeated_blocked_reads_preserve_the_original_diagnostic() {
    let (_temp, case, run) = fixture();
    let path = case.run_dir(&run.id).join("missing.exe");
    volgui::extracted_files::block_artifact(&path, "Original missing output").unwrap();
    let error = volgui::extracted_files::ensure_openable(&path).unwrap_err();
    volgui::extracted_files::block_artifact(&path, &error).unwrap();
    let db = volgui::database::connect(&case.directory).unwrap();
    let reason: String = db
        .query_row(
            "SELECT blocked_reason FROM analysis_outputs WHERE run_id=?1 AND name='missing.exe'",
            [run.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason, "Original missing output");
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
