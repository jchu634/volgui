// Checks extracted files behavior.
use serde_json::json;
use std::fs;
use std::sync::atomic::AtomicBool;
use volgui::{
    case::{Case, DATABASE, Evidence, RunStatus},
    extracted_files::{DUMP_FILES, FileDumpTarget, queue_file_dump},
    results::StoredRecord,
    settings::Settings,
    volatility::{Installation, Plugin, Table},
};

fn record(fields: serde_json::Value) -> volgui::volatility::Record {
    Table::parse(&json!([fields]).to_string())
        .unwrap()
        .rows
        .remove(0)
}

#[test]
fn file_dump_uses_the_file_object_address_and_its_address_space() {
    for (fields, flag, address) in [
        (
            json!({"Offset(V)": u64::MAX, "Name": "a"}),
            "--virtaddr",
            "0xffffffffffffffff",
        ),
        (
            json!({"Offset(P)": "0X12AB", "Name": "a"}),
            "--physaddr",
            "0x12ab",
        ),
        (
            json!({"Offset(V)": "4783", "Name": "a"}),
            "--virtaddr",
            "0x12af",
        ),
    ] {
        let target =
            FileDumpTarget::from_record("windows.filescan.FileScan", &record(fields)).unwrap();
        assert!(!target.needs_address_space());
        for physical in [false, true] {
            assert_eq!(target.arguments(physical), [flag, address]);
        }
    }
    let target = FileDumpTarget::from_record(
        "windows.filescan.FileScan",
        &record(json!({"Offset": 4096})),
    )
    .unwrap();
    assert!(target.needs_address_space());
    assert_eq!(target.arguments(false), ["--virtaddr", "0x1000"]);
    assert_eq!(target.arguments(true), ["--physaddr", "0x1000"]);
    let target = FileDumpTarget::from_record(
        "windows.handles.Handles",
        &record(json!({"Type": "File", "Offset": 4096, "HandleValue": 80})),
    )
    .unwrap();
    assert_eq!(target.arguments(true), ["--virtaddr", "0x1000"]);
}

#[test]
fn unsupported_or_invalid_records_cannot_start_a_broad_dump() {
    for fields in [
        json!({"Name": "a"}),
        json!({"Offset": null}),
        json!({"Offset": 0}),
        json!({"Offset": -1}),
        json!({"Offset": 1.5}),
        json!({"Offset": "N/A"}),
        json!({"Offset": "0x1000 --pid 4"}),
        json!({"Offset": "18446744073709551616"}),
    ] {
        assert!(
            FileDumpTarget::from_record("windows.filescan.FileScan", &record(fields)).is_none()
        );
    }
    for (plugin, fields) in [
        ("linux.lsof.Lsof", json!({"Offset":4096})),
        ("windows.psscan.PsScan", json!({"Offset(V)":4096})),
        (
            "windows.handles.Handles",
            json!({"Type":"Process", "Offset":4096}),
        ),
    ] {
        assert!(FileDumpTarget::from_record(plugin, &record(fields)).is_none());
    }
}

fn dump_case() -> (tempfile::TempDir, Case, Installation, StoredRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Per-file extraction").unwrap();
    for name in ["source.raw", "other.raw"] {
        let path = temp.path().join(name);
        fs::write(&path, name).unwrap();
        case.add_evidence(Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap())
            .unwrap();
    }
    let engine = Installation {
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: ["windows.filescan.FileScan", DUMP_FILES]
            .into_iter()
            .map(|id| Plugin {
                id: id.into(),
                description: String::new(),
            })
            .collect(),
    };
    let source = engine
        .prepare(
            &case.document.evidence[0],
            "windows.filescan.FileScan",
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    let stored = StoredRecord {
        id: 1,
        run_id: source.id.clone(),
        row: 0,
        record: record(json!({"Offset(V)": 4096, "Name": "selected.txt"})),
    };
    case.queue(source).unwrap();
    let table = Table::parse(
        &json!([stored.record.fields, {"Offset(V)": 8192, "Name": "other.txt"}]).to_string(),
    )
    .unwrap();
    case.finish(
        &stored.run_id,
        &volgui::volatility::Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(table),
        },
    )
    .unwrap();
    (temp, case, engine, stored)
}

#[test]
fn queues_one_file_without_a_previous_dump_and_preserves_source_evidence() {
    let (_temp, mut case, engine, stored) = dump_case();
    let id = queue_file_dump(&mut case, &engine, &stored, false).unwrap();
    assert_eq!(case.document.runs.len(), 2);
    let run = case.document.runs.last().unwrap();
    assert_eq!(run.id, id);
    assert_eq!(run.evidence_id, case.document.evidence[0].id);
    assert_eq!(run.plugin, DUMP_FILES);
    assert_eq!(run.arguments, ["--virtaddr", "0x1000"]);
    assert_eq!(run.status, RunStatus::Queued);
    assert_ne!(run.id, stored.run_id);
    let directory = case.directory.clone();
    drop(case);
    let reopened = Case::open(&directory).unwrap();
    assert_eq!(reopened.document.runs.last().unwrap().id, id);
    assert_eq!(reopened.results(&stored.run_id).unwrap().rows.len(), 2);
}

#[test]
fn unavailable_engine_stale_evidence_or_save_failure_does_not_queue_a_dump() {
    let (_temp, mut case, engine, stored) = dump_case();
    let mut unavailable = engine.clone();
    unavailable.plugins.retain(|plugin| plugin.id != DUMP_FILES);
    assert!(queue_file_dump(&mut case, &unavailable, &stored, false).is_err());
    let mut missing = stored.clone();
    missing.run_id = "missing".into();
    assert!(queue_file_dump(&mut case, &engine, &missing, false).is_err());
    let manifest = case.directory.join(DATABASE);
    let saved = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(queue_file_dump(&mut case, &engine, &stored, false).is_err());
    assert_eq!(case.document.runs.len(), 1);
    fs::remove_dir(&manifest).unwrap();
    fs::write(manifest, saved).unwrap();
    fs::write(&case.document.evidence[0].path, "changed capture").unwrap();
    assert!(queue_file_dump(&mut case, &engine, &stored, false).is_err());
    assert_eq!(case.document.runs.len(), 1);
}

#[cfg(feature = "test-engine")]
#[test]
fn individual_dump_executes_and_retains_all_cache_files_and_empty_results() {
    for (offset, flag, expected_files) in [
        (4096, "--virtaddr", 2),
        (4096, "--physaddr", 2),
        (1, "--virtaddr", 0),
    ] {
        let (_temp, mut case, _, mut stored) = dump_case();
        let engine = Installation::discover(
            Settings {
                executable: env!("CARGO_BIN_EXE_volgui-test-engine").into(),
                ..Settings::default()
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        stored.record = record(json!({"Offset": offset, "Name": "selected.txt"}));
        let id = queue_file_dump(&mut case, &engine, &stored, flag == "--physaddr").unwrap();
        let run = case.document.runs.last().unwrap().clone();
        let output = case.run_dir(&id);
        let outcome = engine.execute(&run, &output, &AtomicBool::new(false));
        assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
        case.finish(&id, &outcome).unwrap();
        assert_eq!(case.document.runs.last().unwrap().row_count, expected_files);
        let files = volgui::extracted_files::list(&output).unwrap();
        assert_eq!(files.len(), expected_files);
        for file in files {
            assert_eq!(
                volgui::volatility::read_text(&file, 4096).unwrap(),
                format!("{flag} {offset:#x}")
            );
        }
    }
}

#[test]
fn lists_nested_dumps_but_excludes_engine_logs() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("nested")).unwrap();
    for name in [
        "stdout.json",
        "stderr.log",
        "process.dmp",
        "nested/file.dat",
    ] {
        fs::write(directory.path().join(name), b"dump").unwrap();
    }
    assert_eq!(
        volgui::extracted_files::list(directory.path()).unwrap(),
        vec![
            directory.path().join("nested/file.dat"),
            directory.path().join("process.dmp")
        ]
    );
}

#[test]
fn missing_output_directory_reports_an_error() {
    let directory = tempfile::tempdir().unwrap();
    assert!(volgui::extracted_files::list(&directory.path().join("missing")).is_err());
}

#[test]
fn hex_pages_bound_reads_preserve_offsets_and_format_binary_and_partial_rows() {
    use volgui::extracted_files::{HEX_PAGE_SIZE, HexPage};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bytes.dat");
    let mut bytes = vec![0; 259];
    bytes[..5].copy_from_slice(&[0, 0x41, 0x20, 0x7f, 0xff]);
    bytes[256..].copy_from_slice(b"end");
    fs::write(&path, &bytes).unwrap();
    let first = HexPage::read(&path, 0).unwrap();
    assert_eq!(first.total, 259);
    assert_eq!(first.bytes.len() as u64, HEX_PAGE_SIZE);
    assert!(first.text().contains("00 41 20 7F FF"));
    assert!(first.text().contains("| .A .."));
    let last = HexPage::read(&path, 256).unwrap();
    assert_eq!(last.offset, 256);
    assert_eq!(last.bytes, b"end");
    assert!(last.text().contains("0000000000000100  65 6E 64"));
    assert!(last.text().ends_with("| end\n"));
    assert_eq!(HexPage::read(&path, u64::MAX).unwrap().offset, 256);
    fs::write(&path, []).unwrap();
    let empty = HexPage::read(&path, 256).unwrap();
    assert_eq!(empty.total, 0);
    assert_eq!(empty.offset, 0);
    assert!(empty.bytes.is_empty());
    assert!(HexPage::read(&temp.path().join("missing"), 0).is_err());
    // A multi-gigabyte sparse output still costs one page to inspect.
    fs::File::create(&path)
        .unwrap()
        .set_len(5 * 1024 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        HexPage::read(&path, 4 * 1024 * 1024 * 1024)
            .unwrap()
            .bytes
            .len(),
        256
    );
}

#[test]
fn content_reuse_matches_file_object_address_space_evidence_and_completion() {
    use volgui::extracted_files::completed_dump;
    let (_temp, mut case, engine, stored) = dump_case();
    assert!(completed_dump(&case, &stored, false).is_none());
    let id = queue_file_dump(&mut case, &engine, &stored, false).unwrap();
    assert!(completed_dump(&case, &stored, false).is_none());
    let outcome = volgui::volatility::Outcome {
        status: RunStatus::Completed,
        exit_code: Some(0),
        message: String::new(),
        table: None,
    };
    case.finish(&id, &outcome).unwrap();
    assert_eq!(completed_dump(&case, &stored, false).unwrap().id, id);
    let mut different = stored.clone();
    different.record = record(json!({"Offset(V)":8192}));
    assert!(completed_dump(&case, &different, false).is_none());
    different.record = record(json!({"Offset":4096}));
    assert!(completed_dump(&case, &different, true).is_none());
    assert_eq!(completed_dump(&case, &different, false).unwrap().id, id);
    // A newer matching address from another capture cannot replace this result.
    let wrong = engine
        .prepare(
            &case.document.evidence[1],
            DUMP_FILES,
            vec!["--virtaddr".into(), "0x1000".into()],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(wrong.clone()).unwrap();
    case.finish(&wrong.id, &outcome).unwrap();
    assert_eq!(completed_dump(&case, &stored, false).unwrap().id, id);
}
