use std::{fs, num::NonZeroUsize, sync::atomic::AtomicBool};

use serde_json::json;
use volgui::{
    analyses::{self, AnalysisDraft},
    analysis::{
        self,
        files::{self, RecoveryIndex, RecoveryState},
    },
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, Run, RunStatus},
    extracted_files::{self, DUMP_FILES, FileDumpTarget},
    results::{Query, ResultStore, StoredRecord},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn fixture(rows: serde_json::Value) -> (tempfile::TempDir, Case, Installation, String) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "File recovery").unwrap();
    for name in ["source.raw", "other.raw"] {
        let path = temp.path().join(name);
        fs::write(&path, name).unwrap();
        let mut evidence = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap();
        evidence.operating_system = OperatingSystem::Windows;
        case.add_evidence(evidence).unwrap();
    }
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: files::SOURCES
            .into_iter()
            .chain([DUMP_FILES])
            .map(|id| Plugin {
                id: id.into(),
                description: String::new(),
            })
            .collect(),
    };
    let run = engine
        .prepare(
            &case.document.evidence[0],
            files::SOURCES[0],
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    let id = run.id.clone();
    case.queue(run).unwrap();
    finish(&mut case, &id, rows);
    (temp, case, engine, id)
}

fn finish(case: &mut Case, id: &str, rows: serde_json::Value) {
    case.finish(
        id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(Table::parse(&rows.to_string()).unwrap()),
        },
    )
    .unwrap();
}

fn records(case: &Case, run: &str) -> Vec<StoredRecord> {
    let store = ResultStore::at(&case.directory);
    let index = store
        .query(&Query {
            runs: vec![run.into()],
            ..Default::default()
        })
        .unwrap();
    store.fetch(&index.ids).unwrap()
}

#[test]
fn executable_references_without_file_objects_appear_in_the_file_tree() {
    let (_temp, mut case, mut engine, _) = fixture(json!([]));
    // Discovery must work without inventories, an engine, or bulk recovery.
    case.document.runs.clear();
    engine.plugins.clear();
    let name =
        r"C:\Users\sepehr\Documents\49f5_354bd7ad_611729000b81358a_22ee7136c30a2f24\runas.exe";
    let source = case.document.evidence[0].path.clone();
    fs::write(&source, format!("\0{name}\0")).unwrap();
    let mut evidence = Evidence::inspect(&source, &AtomicBool::new(false), |_, _| {}).unwrap();
    evidence.id = case.document.evidence[0].id.clone();
    case.document.evidence[0] = evidence;
    let mut draft = AnalysisDraft::new(&case.document.evidence[0]);
    draft.selected.insert(analysis::FILE_PATHS.into());
    let runs = draft
        .prepare_in_case(&engine, &case.document.evidence[0], &case)
        .unwrap();
    assert_eq!(runs.len(), 1);
    let report = runs[0].clone();
    assert_eq!(report.plugin, analysis::FILE_PATHS);
    assert!(report.message.is_empty());
    assert!(analysis::is_native(&report.plugin));
    assert_eq!(
        ArtifactGroup::for_plugin(&report.plugin),
        ArtifactGroup::Files
    );
    case.queue_batch(runs).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &report,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
    case.finish(&report.id, &outcome).unwrap();
    let row = records(&case, &report.id).remove(0);
    assert_eq!(row.record.text("Name"), name);
    assert!(FileDumpTarget::from_record(analysis::FILE_PATHS, &row.record).is_none());
    let recovery = RecoveryIndex::load(&case.directory, &case.document).unwrap();
    assert_eq!(recovery.state(&row, false), RecoveryState::Referenced);
    let store = ResultStore::at(&case.directory);
    let (entries, _) = files::filter_entries(
        &store,
        &recovery,
        store
            .tree_entries(std::slice::from_ref(&report.id))
            .unwrap(),
        false,
        false,
    )
    .unwrap();
    let tree = volgui::result_tree::ResultTree::files(entries, &[row.id]);
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.label == "runas.exe" && n.record_id == Some(row.id))
    );
    let matches = store
        .query(&Query {
            runs: vec![report.id.clone()],
            text: "runas.exe".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(matches.ids, [row.id]);
    let cancelled = analysis::execute(
        &case.directory,
        &case.document,
        &report,
        &AtomicBool::new(true),
        |_| {},
    );
    assert_eq!(cancelled.status, RunStatus::Cancelled);
}

#[test]
fn executable_discovery_is_a_basic_analysis_and_rejects_options() {
    let (_temp, case, engine, _) = fixture(json!([]));
    let catalog = analyses::application_plugins(&engine.plugins);
    assert!(
        analyses::chooser_plugins(&catalog, OperatingSystem::Windows, false, "executable")
            .iter()
            .any(|plugin| plugin.id == analysis::FILE_PATHS)
    );
    assert!(
        analysis::prepare(
            &case.document.evidence[0],
            analysis::FILE_PATHS,
            vec!["--pid".into(), "42".into()]
        )
        .is_err()
    );
}

#[test]
#[ignore = "Requires VOLGUI_TEST_MEMORY_DUMP pointing to memory_dump_95.bin"]
fn real_memory_dump_contains_the_documents_executable_reference() {
    let path = std::env::var_os("VOLGUI_TEST_MEMORY_DUMP").expect("Set VOLGUI_TEST_MEMORY_DUMP");
    let (_temp, mut case, _, _) = fixture(json!([]));
    case.document.runs.clear();
    let mut evidence = Evidence::inspect(
        std::path::Path::new(&path),
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    evidence.id = case.document.evidence[0].id.clone();
    case.document.evidence[0] = evidence;
    let report =
        analysis::prepare(&case.document.evidence[0], analysis::FILE_PATHS, vec![]).unwrap();
    case.queue(report.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &report,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
    let table = outcome.table.as_ref().unwrap();
    let row = table
        .rows
        .iter()
        .find(|r| {
            r.text("Name")
                .to_lowercase()
                .ends_with(r"\documents\49f5_354bd7ad_611729000b81358a_22ee7136c30a2f24\runas.exe")
        })
        .expect("Documents executable reference");
    println!(
        "{} at evidence offset {} ({})",
        row.text("Name"),
        row.text("Evidence offset"),
        row.text("Encoding")
    );
    case.finish(&report.id, &outcome).unwrap();
    let store = ResultStore::at(&case.directory);
    let index = store
        .query(&Query {
            runs: vec![report.id.clone()],
            text: "runas.exe".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(!index.ids.is_empty());
    let recovery = RecoveryIndex::load(&case.directory, &case.document).unwrap();
    let (entries, _) = files::filter_entries(
        &store,
        &recovery,
        store.tree_entries(&[report.id]).unwrap(),
        false,
        false,
    )
    .unwrap();
    assert!(entries.iter().any(|e| index.ids.contains(&e.id)));
}

fn dump(
    case: &mut Case,
    engine: &Installation,
    evidence: usize,
    address: u64,
    physical: bool,
    content: Option<&[u8]>,
) -> Run {
    let mut run = engine
        .prepare(
            &case.document.evidence[evidence],
            DUMP_FILES,
            vec![
                if physical { "--physaddr" } else { "--virtaddr" }.into(),
                format!("{address:#x}"),
            ],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(run.clone()).unwrap();
    let directory = case.run_dir(&run.id);
    fs::create_dir_all(&directory).unwrap();
    let rows = if let Some(bytes) = content {
        fs::write(directory.join("file.fixture.dat"), bytes).unwrap();
        json!([{"FileObject":address,"FileName":"document.txt","File output":"file.fixture.dat"}])
    } else {
        json!([])
    };
    fs::write(directory.join("stdout.json"), rows.to_string()).unwrap();
    fs::write(directory.join("stderr.log"), "fixture").unwrap();
    finish(case, &run.id, rows);
    run.status = RunStatus::Completed;
    run
}

#[test]
fn directories_are_omitted_without_discarding_ntfs_files_or_dollar_names() {
    for path in [
        r"\$Directory",
        r"\Device\Volume\$DIRECTORY",
        r"C:\Users\name:$I30:$INDEX_ALLOCATION",
        r"C:\Users:$I30:$INDEX_ROOT",
    ] {
        assert!(files::pseudo_file(path), "{path}");
        let row = Table::parse(&json!([{"Name":path,"Offset":4096}]).to_string())
            .unwrap()
            .rows
            .remove(0);
        assert!(FileDumpTarget::from_record(files::SOURCES[0], &row).is_none());
    }
    for path in [
        r"C:\$Mft",
        r"C:\$LogFile",
        r"C:\$Budget.xlsx",
        r"C:\$Directory.txt",
        r"C:\$Directory\notes.txt",
    ] {
        assert!(!files::pseudo_file(path), "{path}");
    }
}

#[test]
fn recovery_choice_collects_prerequisites_once_and_waits_to_expand() {
    let (_temp, mut case, engine, _) = fixture(json!([]));
    // No completed inventory for the second capture.
    let evidence = case.document.evidence[1].clone();
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::FILES.into());
    let runs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    assert_eq!(
        runs.iter().map(|r| r.plugin.as_str()).collect::<Vec<_>>(),
        [files::SOURCES[0], files::SOURCES[1], analysis::FILES]
    );
    assert_eq!(runs[2].message, files::PENDING);
    assert_eq!(analyses::basic_label(analysis::FILES), None);
    assert_eq!(
        ArtifactGroup::for_plugin(analysis::FILES),
        ArtifactGroup::Files
    );
    let catalog = analyses::application_plugins(&engine.plugins);
    assert!(
        analyses::chooser_plugins(&catalog, OperatingSystem::Windows, true, "document")
            .iter()
            .any(|p| p.id == analysis::FILES)
    );
    assert!(
        !analyses::chooser_plugins(&catalog, OperatingSystem::Linux, true, "")
            .iter()
            .any(|p| p.id == analysis::FILES)
    );
    case.queue_batch(runs).unwrap();
    let repeated = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    assert_eq!(repeated.len(), 1);
    let mut unavailable = engine.clone();
    unavailable.plugins.retain(|p| p.id != DUMP_FILES);
    assert!(
        draft
            .prepare_in_case(&unavailable, &evidence, &case)
            .is_err()
    );
    draft
        .arguments
        .insert(analysis::FILES.into(), "--pid 42".into());
    assert!(draft.prepare_in_case(&engine, &evidence, &case).is_err());
}

#[test]
fn deferred_expansion_deduplicates_objects_and_does_not_use_later_inventories() {
    let (_temp, mut case, engine, scan) = fixture(json!([
        {"Name":"one.txt","Offset(V)":4096},
        {"Name":"one-alias.txt","Offset(V)":4096},
        {"Name":"two.txt","Offset(V)":8192},
        {"Name":"$Directory","Offset(V)":12288},
        {"Name":"broken.txt"}
    ]));
    let mut draft = AnalysisDraft::new(&case.document.evidence[0]);
    draft.selected.insert(analysis::FILES.into());
    let initial = draft
        .prepare_in_case(&engine, &case.document.evidence[0], &case)
        .unwrap();
    let report = initial.last().unwrap().clone();
    case.queue_batch(initial).unwrap();
    let later = engine
        .prepare(
            &case.document.evidence[0],
            files::SOURCES[0],
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(later.clone()).unwrap();
    finish(
        &mut case,
        &later.id,
        json!([{"Name":"later.txt","Offset(V)":16384}]),
    );
    let runs = analyses::prepare_file_recovery(&case, &engine, &report).unwrap();
    assert_eq!(runs.len(), 3);
    assert_eq!(runs.last().unwrap().id, report.id);
    assert_eq!(runs.last().unwrap().created_at, report.created_at);
    assert_eq!(
        runs.iter()
            .filter(|r| r.plugin == DUMP_FILES)
            .map(|r| r.arguments[1].as_str())
            .collect::<Vec<_>>(),
        ["0x1000", "0x2000"]
    );
    assert_eq!(records(&case, &scan).len(), 5);
    // Execution also excludes later inventories if an out-of-order importer has
    // already completed them. The report still describes the original inputs.
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &report,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed);
    let rows = outcome.table.unwrap().rows;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|row| row.text("Source run") == scan));
    let mut queue = vec![runs[0].clone(), runs[2].clone(), runs[1].clone()];
    queue[0].status = RunStatus::Running;
    assert!(analyses::next_queued_run(&queue, NonZeroUsize::new(4).unwrap()).is_none());
    queue[0].status = RunStatus::Completed;
    assert_eq!(
        analyses::next_queued_run(&queue, NonZeroUsize::new(4).unwrap()),
        Some(1)
    );
}

#[test]
fn filtering_preserves_unknowns_and_separates_evidence_and_address_spaces() {
    let (_temp, mut case, engine, scan) = fixture(json!([
        {"Name":"recovered.txt","Offset(V)":4096},
        {"Name":"uncached.txt","Offset(V)":8192},
        {"Name":"unknown.txt","Offset(V)":12288},
        {"Name":"physical.txt","Offset(P)":8192},
        {"Name":"$Directory","Offset(V)":16384},
        {"Name":"invalid.txt","Offset(V)":0},
        {"Name":"\\Device\\NamedPipe\\pipe","Offset(V)":20480}
    ]));
    let recovered = dump(&mut case, &engine, 0, 4096, false, Some(b"document bytes"));
    dump(&mut case, &engine, 0, 8192, false, None);
    dump(&mut case, &engine, 1, 12288, false, None);
    // An empty retry must not hide or replace an earlier usable extraction.
    dump(&mut case, &engine, 0, 4096, false, None);
    volgui::object_store::ObjectStore::at(&case.directory)
        .capture_run(&recovered.id, &AtomicBool::new(false))
        .unwrap();
    let index = RecoveryIndex::load(&case.directory, &case.document).unwrap();
    let rows = records(&case, &scan);
    assert_eq!(index.state(&rows[0], false), RecoveryState::Recovered);
    assert_eq!(
        index.recovery(&rows[0], false).unwrap().run_id,
        recovered.id
    );
    assert_eq!(index.state(&rows[1], false), RecoveryState::Uncached);
    assert_eq!(index.state(&rows[2], false), RecoveryState::Untested);
    assert_eq!(index.state(&rows[3], false), RecoveryState::Untested);
    let store = ResultStore::at(&case.directory);
    let (hidden, _) = files::filter_entries(
        &store,
        &index,
        store.tree_entries(std::slice::from_ref(&scan)).unwrap(),
        false,
        false,
    )
    .unwrap();
    assert_eq!(hidden.len(), 3);
    let (shown, _) = files::filter_entries(
        &store,
        &index,
        store.tree_entries(&[scan]).unwrap(),
        false,
        true,
    )
    .unwrap();
    assert_eq!(shown.len(), 6);
    assert!(
        !shown
            .iter()
            .any(|entry| entry.path.as_deref() == Some("$Directory"))
    );
    let directory = case.directory.clone();
    drop(case);
    let case = Case::open(&directory).unwrap();
    let reopened = RecoveryIndex::load(&case.directory, &case.document).unwrap();
    assert_eq!(reopened.state(&rows[0], false), RecoveryState::Recovered);
    assert_eq!(reopened.state(&rows[1], false), RecoveryState::Uncached);
}

#[test]
fn report_keeps_provenance_and_physical_offsets_and_is_cancellable() {
    let (_temp, mut case, engine, scan) = fixture(json!([
        {"Name":"document.txt","Offset":4096},
        {"Name":"missing.txt","Offset":8192},
        {"Name":"$Directory","Offset":12288}
    ]));
    let recovered = dump(&mut case, &engine, 0, 4096, true, Some(b"partial document"));
    dump(&mut case, &engine, 0, 8192, true, None);
    let report = analysis::prepare(
        &case.document.evidence[0],
        analysis::FILES,
        vec!["--physical".into()],
    )
    .unwrap();
    case.queue(report.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &report,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
    let rows = &outcome.table.as_ref().unwrap().rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].text("Source run"), scan);
    assert_eq!(rows[0].text("Extraction run"), recovered.id);
    assert_eq!(rows[0].text("Recovery status"), "Recovered");
    assert_eq!(rows[1].text("Recovery status"), "No cached contents");
    assert_eq!(
        FileDumpTarget::from_record(analysis::FILES, &rows[0])
            .unwrap()
            .arguments(false),
        ["--physaddr", "0x1000"]
    );
    case.finish(&report.id, &outcome).unwrap();
    let selected = records(&case, &report.id).remove(0);
    assert_eq!(
        extracted_files::completed_dump(&case, &selected, false)
            .unwrap()
            .id,
        recovered.id
    );
    let cancelled = analysis::execute(
        &case.directory,
        &case.document,
        &report,
        &AtomicBool::new(true),
        |_| {},
    );
    assert_eq!(cancelled.status, RunStatus::Cancelled);
}

#[test]
fn failed_and_blocked_attempts_remain_distinct_and_file_reports_retry_as_deferred_jobs() {
    let (_temp, mut case, engine, scan) = fixture(json!([
        {"Name":"failed.txt","Offset(V)":4096},
        {"Name":"blocked.txt","Offset(V)":8192}
    ]));
    let failed = engine
        .prepare(
            &case.document.evidence[0],
            DUMP_FILES,
            vec!["--virtaddr".into(), "0x1000".into()],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(failed.clone()).unwrap();
    case.finish(
        &failed.id,
        &Outcome {
            status: RunStatus::Failed,
            exit_code: Some(1),
            message: "Unreadable object".into(),
            table: None,
        },
    )
    .unwrap();
    let blocked = dump(
        &mut case,
        &engine,
        0,
        8192,
        false,
        Some(b"bytes removed by scanner"),
    );
    let output = case.run_dir(&blocked.id).join("file.fixture.dat");
    let db = volgui::database::connect(&case.directory).unwrap();
    let blob: String = db
        .query_row(
            "SELECT blob_id FROM analysis_outputs WHERE run_id=?1 AND name='file.fixture.dat'",
            [&blocked.id],
            |r| r.get(0),
        )
        .unwrap();
    fs::remove_file(case.directory.join("objects/blobs").join(blob)).unwrap();
    assert!(extracted_files::open_artifact(&output).is_err());
    let index = RecoveryIndex::load(&case.directory, &case.document).unwrap();
    let rows = records(&case, &scan);
    assert_eq!(index.state(&rows[0], false), RecoveryState::Failed);
    assert_eq!(index.state(&rows[1], false), RecoveryState::Unavailable);
    assert_eq!(
        case.document
            .runs
            .iter()
            .find(|r| r.id == failed.id)
            .unwrap()
            .message,
        "Unreadable object"
    );
    let report = analysis::prepare(&case.document.evidence[0], analysis::FILES, vec![]).unwrap();
    case.queue(report.clone()).unwrap();
    case.finish(
        &report.id,
        &Outcome {
            status: RunStatus::Failed,
            exit_code: None,
            message: "fixture report failure".into(),
            table: None,
        },
    )
    .unwrap();
    analyses::queue_retries(&mut case, &engine, &[report.id]).unwrap();
    let retry = case.document.runs.last().unwrap();
    assert_eq!(retry.plugin, analysis::FILES);
    assert_eq!(retry.message, files::PENDING);
}

#[cfg(feature = "test-engine")]
#[test]
fn real_queue_outputs_feed_the_report_and_empty_dumps_stay_hidden() {
    let (_temp, mut case, _, scan) = fixture(json!([
        {"Name":"document.txt","Offset(V)":4096},
        {"Name":"empty.txt","Offset(V)":1}
    ]));
    let engine = Installation::discover(
        Settings {
            executable: env!("CARGO_BIN_EXE_volgui-test-engine").into(),
            ..Settings::default()
        },
        &AtomicBool::new(false),
    )
    .unwrap();
    let jobs = files::recovery_runs(
        &case.directory,
        &case.document,
        &case.document.evidence[0],
        &engine,
        &[],
    )
    .unwrap();
    case.queue_batch(jobs.clone()).unwrap();
    for run in &jobs {
        let outcome = if run.plugin == analysis::FILES {
            analysis::execute(
                &case.directory,
                &case.document,
                run,
                &AtomicBool::new(false),
                |_| {},
            )
        } else {
            engine.execute(run, &case.run_dir(&run.id), &AtomicBool::new(false))
        };
        assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
        case.finish(&run.id, &outcome).unwrap();
        volgui::object_store::ObjectStore::at(&case.directory)
            .capture_run(&run.id, &AtomicBool::new(false))
            .unwrap();
    }
    let index = RecoveryIndex::load(&case.directory, &case.document).unwrap();
    let rows = records(&case, &scan);
    assert_eq!(index.state(&rows[0], false), RecoveryState::Recovered);
    assert_eq!(index.state(&rows[1], false), RecoveryState::Uncached);
    let report = records(&case, &jobs.last().unwrap().id);
    assert_eq!(report[0].record.text("Recovery status"), "Recovered");
    assert_eq!(
        report[1].record.text("Recovery status"),
        "No cached contents"
    );
    let repeated = files::recovery_runs(
        &case.directory,
        &case.document,
        &case.document.evidence[0],
        &engine,
        &[],
    )
    .unwrap();
    assert_eq!(repeated.len(), 1);
}
