use serde_json::{Value, json};
use std::{fs, num::NonZeroUsize, sync::atomic::AtomicBool};
use volgui::{
    analyses::{self, AnalysisDraft},
    analysis::{self, quarantine},
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, Run, RunStatus},
    extracted_files::{self, DUMP_FILES},
    results::{Query, ResultStore},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

const ENTRY: &str = r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\Entries\{fixture}";
const ORIGINAL: &str = r"C:\Users\Alice\Downloads\payload.exe";
const METADATA: &[u8] = include_bytes!("fixtures/defender-entry.bin");

fn fixture() -> (tempfile::TempDir, Case, Installation) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Quarantine").unwrap();
    for name in ["capture.raw", "other.raw"] {
        let path = temp.path().join(name);
        fs::write(&path, b"Synthetic quarantine investigation fixture").unwrap();
        let mut evidence = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap();
        evidence.operating_system = OperatingSystem::Windows;
        case.add_evidence(evidence).unwrap();
    }
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: quarantine::SOURCES
            .iter()
            .copied()
            .chain([DUMP_FILES])
            .map(|id| Plugin {
                id: id.into(),
                description: String::new(),
            })
            .collect(),
    };
    (temp, case, engine)
}
fn save(
    case: &mut Case,
    engine: &Installation,
    evidence: usize,
    plugin: &str,
    arguments: Vec<String>,
    rows: Value,
) -> Run {
    let mut run = engine
        .prepare(
            &case.document.evidence[evidence],
            plugin,
            arguments,
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(run.clone()).unwrap();
    finish(case, &run.id, rows);
    run.status = RunStatus::Completed;
    run
}
fn finish(case: &mut Case, id: &str, rows: Value) {
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
fn dump(
    case: &mut Case,
    engine: &Installation,
    evidence: usize,
    address: &str,
    content: Option<&[u8]>,
) -> Run {
    let mut run = engine
        .prepare(
            &case.document.evidence[evidence],
            DUMP_FILES,
            vec!["--virtaddr".into(), address.into()],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(run.clone()).unwrap();
    let directory = case.run_dir(&run.id);
    fs::create_dir_all(&directory).unwrap();
    let rows = if let Some(bytes) = content {
        fs::write(directory.join("file.fixture.dat"), bytes).unwrap();
        json!([{"File output":"file.fixture.dat"}])
    } else {
        json!([])
    };
    fs::write(directory.join("stdout.json"), rows.to_string()).unwrap();
    finish(case, &run.id, rows);
    run.status = RunStatus::Completed;
    run
}
fn complete_sources(case: &mut Case, engine: &Installation) {
    let missing = analysis::missing_source_inventories(
        &case.document.runs,
        &case.document.evidence[0].id,
        quarantine::SOURCES,
        false,
    );
    for plugin in missing {
        save(case, engine, 0, plugin, vec![], json!([]));
    }
}
fn execute(case: &mut Case) -> (Run, Outcome) {
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: quarantine::SOURCES
            .iter()
            .map(|id| Plugin {
                id: (*id).into(),
                description: String::new(),
            })
            .collect(),
    };
    complete_sources(case, &engine);
    let run = analysis::prepare(&case.document.evidence[0], analysis::QUARANTINE, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(outcome.status.has_results(), "{}", outcome.message);
    case.finish(&run.id, &outcome).unwrap();
    (run, outcome)
}
fn scan(case: &mut Case, engine: &Installation) -> Run {
    save(
        case,
        engine,
        0,
        quarantine::SOURCES[0],
        vec![],
        json!([
            {"Name":ENTRY,"Offset(V)":4096},
            {"Name":ORIGINAL,"Offset(V)":8192},
            {"Name":r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\AA\opaque", "Offset(V)":12288},
            {"Name":r"C:\ProgramData\Malwarebytes\MBAMService\Quarantine\opaque", "Offset(V)":16384},
            {"Name":r"C:\Users\Alice\quarantine\innocent.exe", "Offset(V)":20480}
        ]),
    )
}

#[test]
fn defender_metadata_process_and_origin_keep_provenance_and_survive_reopen() {
    let (_temp, mut case, engine) = fixture();
    let scan = scan(&mut case, &engine);
    let metadata = dump(&mut case, &engine, 0, "0x1000", Some(METADATA));
    let process = save(
        &mut case,
        &engine,
        0,
        "windows.pslist.PsList",
        vec![],
        json!([
            {"PID":100,"ImageFileName":"payload.exe","CreateTime":"2022-01-01T00:00:00Z"}
        ]),
    );
    let command = save(
        &mut case,
        &engine,
        0,
        "windows.cmdline.CmdLine",
        vec![],
        json!([
            {"PID":100,"Args":format!("\"{ORIGINAL}\" --test")}
        ]),
    );
    let origin = save(
        &mut case,
        &engine,
        0,
        "windows.mftscan.ADS",
        vec![],
        json!([
            {"Filename":ORIGINAL,"ADS Filename":"Zone.Identifier","Content":"[ZoneTransfer]\r\nHostUrl=https://cdn.example.test/renamed.exe\r\nReferrerUrl=https://example.test/downloads\r\n"}
        ]),
    );
    let (run, outcome) = execute(&mut case);
    let table = outcome.table.unwrap();
    let row = table
        .rows
        .iter()
        .find(|r| r.text("Evidence status").starts_with("Confirmed"))
        .unwrap();
    assert_eq!(row.text("Scope"), "Memory capture");
    assert_eq!(row.text("Antivirus"), "Microsoft Defender");
    assert_eq!(row.text("Original path"), ORIGINAL);
    assert_eq!(row.text("Threat"), "Trojan:Win32/SyntheticTest");
    assert_eq!(row.text("File size"), "12345");
    assert_eq!(
        row.text("Resource ID"),
        "000102030405060708090A0B0C0D0E0F10111213"
    );
    assert!(!row.text("Quarantined at").is_empty());
    assert_eq!(row.text("PID"), "100");
    assert!(
        row.text("Execution evidence")
            .starts_with("Active process candidate")
    );
    assert!(row.text("Match basis").starts_with("Full path"));
    assert_eq!(row.text("URL"), "https://cdn.example.test/renamed.exe");
    assert!(row.text("Origin evidence").contains("Full path"));
    for id in [&scan.id, &metadata.id, &process.id, &origin.id, &command.id] {
        assert!(row.text("Sources").contains(id), "Missing source {id}");
    }
    assert_eq!(table.rows.len(), 3);
    assert!(
        table
            .rows
            .iter()
            .filter(|r| r.text("Evidence status").contains("candidate"))
            .all(|r| r.text("PID").is_empty() && r.text("Original path").is_empty())
    );
    let columns = volgui::result_table::columns(Some(ArtifactGroup::Quarantine), &table.columns);
    assert!(columns.iter().any(|c| c.label == "Scope"));
    let path = case.directory.clone();
    drop(case);
    let case = Case::open(&path).unwrap();
    let saved = case.results(&run.id).unwrap();
    assert_eq!(saved.rows.len(), 3);
    assert!(saved.csv(&[0, 1, 2]).contains("Trojan:Win32/SyntheticTest"));
    assert_eq!(
        ResultStore::at(&path)
            .query(&Query {
                runs: vec![run.id],
                filters: [("Scope".into(), ["Memory capture".into()].into())].into(),
                ..Default::default()
            })
            .unwrap()
            .ids
            .len(),
        3
    );
}

#[test]
fn local_blocking_has_its_own_scope_and_empty_extractions_are_not_detections() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    let missing = dump(&mut case, &engine, 0, "0x2000", None);
    let blocked = case.run_dir(&missing.id).join("file.removed.dat");
    extracted_files::block_artifact(
        &blocked,
        "Output removed after recovery; antivirus cause unconfirmed",
    )
    .unwrap();
    // Other capture's blocked output must not enter this report.
    let other = dump(&mut case, &engine, 1, "0x2000", None);
    extracted_files::block_artifact(
        &case.run_dir(&other.id).join("file.other.dat"),
        "unavailable",
    )
    .unwrap();
    let empty = dump(&mut case, &engine, 0, "0x5000", None);
    let (_, outcome) = execute(&mut case);
    let rows = outcome.table.unwrap().rows;
    let local = rows
        .iter()
        .filter(|r| r.text("Scope") == "Local computer")
        .collect::<Vec<_>>();
    assert_eq!(local.len(), 1);
    assert_eq!(local[0].text("Antivirus"), "Unconfirmed");
    assert_eq!(local[0].text("Original path"), ORIGINAL);
    assert!(local[0].text("Blocked reason").contains("Output removed"));
    assert!(!rows.iter().any(|r| r.text("Sources").contains(&empty.id)));
    assert!(!rows.iter().any(|r| r.text("Sources").contains(&other.id)));
}

#[test]
fn corrupted_metadata_stays_a_candidate_and_argument_or_conflicting_paths_do_not_prove_execution() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    let mut corrupt = METADATA.to_vec();
    *corrupt.last_mut().unwrap() ^= 0xff;
    dump(&mut case, &engine, 0, "0x1000", Some(&corrupt));
    let (_, outcome) = execute(&mut case);
    let rows = outcome.table.unwrap().rows;
    assert!(
        !rows
            .iter()
            .any(|r| r.text("Evidence status").starts_with("Confirmed"))
    );
    assert!(
        rows.iter()
            .any(|r| r.text("Recovery details").contains("checksum"))
    );
    dump(&mut case, &engine, 0, "0x1000", Some(METADATA));
    save(
        &mut case,
        &engine,
        0,
        "windows.pslist.PsList",
        vec![],
        json!([
            {"PID":1,"ImageFileName":"notepad.exe"}, {"PID":2,"ImageFileName":"payload.exe"},
            {"PID":3,"ImageFileName":"payload.exe"}
        ]),
    );
    save(
        &mut case,
        &engine,
        0,
        "windows.cmdline.CmdLine",
        vec![],
        json!([
            {"PID":1,"Args":format!("notepad.exe {ORIGINAL}")},
            {"PID":2,"Args":r"D:\Different\payload.exe"},
            {"PID":3,"Args":"payload.exe"}
        ]),
    );
    let (_, outcome) = execute(&mut case);
    let matched = outcome
        .table
        .unwrap()
        .rows
        .into_iter()
        .filter(|r| r.text("Evidence status").starts_with("Confirmed"))
        .collect::<Vec<_>>();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].text("PID"), "3");
    assert!(matched[0].text("Match basis").starts_with("Filename only"));
}

#[test]
fn later_filtered_and_other_evidence_never_supply_process_matches() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    dump(&mut case, &engine, 0, "0x1000", Some(METADATA));
    save(
        &mut case,
        &engine,
        0,
        "windows.pslist.PsList",
        vec!["--pid".into(), "10".into()],
        json!([
            {"PID":10,"ImageFileName":"payload.exe"}
        ]),
    );
    save(
        &mut case,
        &engine,
        1,
        "windows.pslist.PsList",
        vec![],
        json!([
            {"PID":20,"ImageFileName":"payload.exe"}
        ]),
    );
    complete_sources(&mut case, &engine);
    let run = analysis::prepare(&case.document.evidence[0], analysis::QUARANTINE, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    save(
        &mut case,
        &engine,
        0,
        "windows.pslist.PsList",
        vec![],
        json!([
            {"PID":30,"ImageFileName":"payload.exe"}
        ]),
    );
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        outcome
            .table
            .unwrap()
            .rows
            .iter()
            .all(|r| r.text("PID").is_empty())
    );
    let cancelled = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(true),
        |_| {},
    );
    assert_eq!(cancelled.status, RunStatus::Cancelled);
}

#[test]
fn scanned_process_lifetimes_do_not_inherit_an_active_pids_command_line() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    dump(&mut case, &engine, 0, "0x1000", Some(METADATA));
    save(
        &mut case,
        &engine,
        0,
        "windows.psscan.PsScan",
        vec![],
        json!([
            {"PID":100,"ImageFileName":"payload.exe","CreateTime":"2021-01-01T00:00:00Z","ExitTime":"2021-01-01T01:00:00Z"}
        ]),
    );
    let command = save(
        &mut case,
        &engine,
        0,
        "windows.cmdline.CmdLine",
        vec![],
        json!([
            {"PID":100,"Args":ORIGINAL}
        ]),
    );
    let (_, outcome) = execute(&mut case);
    let table = outcome.table.unwrap();
    let row = table
        .rows
        .iter()
        .find(|r| r.text("Evidence status").starts_with("Confirmed"))
        .unwrap();
    assert_eq!(row.text("Execution evidence"), "Exited process candidate");
    assert!(row.text("Match basis").starts_with("Filename only"));
    assert!(!row.text("Sources").contains(&command.id));
}

#[test]
fn chooser_and_deferred_recovery_only_extract_metadata_and_preserve_the_report_identity() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    let evidence = case.document.evidence[0].clone();
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::QUARANTINE.into());
    let runs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    let pending = runs.last().unwrap().clone();
    assert_eq!(pending.message, quarantine::PENDING);
    assert_eq!(
        runs.iter()
            .filter(|r| r.plugin == quarantine::SOURCES[0])
            .count(),
        0
    );
    assert!(!runs.iter().any(|r| r.plugin == DUMP_FILES));
    let mut running = pending.clone();
    running.status = RunStatus::Running;
    let mut queued = pending.clone();
    queued.id = "other".into();
    assert!(analyses::next_queued_run(&[running, queued], NonZeroUsize::new(2).unwrap()).is_none());
    case.queue_batch(runs).unwrap();
    assert!(
        analyses::prepare_quarantine_recovery(&case, &engine, &pending)
            .unwrap_err()
            .contains("Missing source inventories")
    );
    for r in &mut case.document.runs {
        if r.id != pending.id {
            r.status = RunStatus::Completed;
        }
    }
    let expanded = analyses::prepare_quarantine_recovery(&case, &engine, &pending).unwrap();
    assert_eq!(expanded.len(), 2);
    assert_eq!(expanded[0].plugin, DUMP_FILES);
    assert_eq!(expanded[0].arguments, ["--virtaddr", "0x1000"]);
    assert_eq!(expanded[1].id, pending.id);
    assert!(expanded[1].message.is_empty());
    assert_eq!(
        ArtifactGroup::for_plugin(analysis::QUARANTINE),
        ArtifactGroup::Quarantine
    );
    assert!(
        analyses::chooser_plugins(
            &analyses::application_plugins(&engine.plugins),
            OperatingSystem::Windows,
            false,
            "quarantined"
        )
        .iter()
        .any(|p| p.id == analysis::QUARANTINE)
    );
    draft.os = OperatingSystem::Linux;
    assert!(draft.prepare_in_case(&engine, &evidence, &case).is_err());
    assert!(analysis::prepare(&evidence, analysis::QUARANTINE, vec!["--restore".into()]).is_err());
}

#[test]
#[ignore = "Requires VOLGUI_TEST_DEFENDER_ENTRY pointing to an independently captured Defender Entries metadata file"]
fn independently_captured_defender_metadata() {
    let path =
        std::env::var_os("VOLGUI_TEST_DEFENDER_ENTRY").expect("Set VOLGUI_TEST_DEFENDER_ENTRY");
    let bytes = fs::read(path).unwrap();
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    dump(&mut case, &engine, 0, "0x1000", Some(&bytes));
    let (_, outcome) = execute(&mut case);
    let rows = outcome.table.unwrap().rows;
    assert!(
        rows.iter()
            .any(|r| r.text("Evidence status").starts_with("Confirmed")),
        "{rows:?}"
    );
}

#[test]
fn retry_without_an_engine_uses_collected_evidence_without_a_recovery_barrier() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    complete_sources(&mut case, &engine);
    let report =
        analysis::prepare(&case.document.evidence[0], analysis::QUARANTINE, vec![]).unwrap();
    case.queue(report.clone()).unwrap();
    case.finish(
        &report.id,
        &Outcome {
            status: RunStatus::Failed,
            exit_code: None,
            message: "Synthetic interrupted read".into(),
            table: None,
        },
    )
    .unwrap();
    analyses::queue_retries_with_engine(&mut case, None, &[report.id]).unwrap();
    let retry = case.document.runs.last().unwrap();
    assert!(retry.message.is_empty());
    assert_eq!(retry.plugin, analysis::QUARANTINE);
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        retry,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(outcome.status.has_results(), "{}", outcome.message);
}

fn passive(case: &mut Case) -> (Run, Outcome) {
    let runs = quarantine::passive_runs(&case.directory, &case.document).unwrap();
    assert_eq!(runs.len(), 1);
    let run = runs[0].clone();
    assert!(quarantine::is_passive(&run));
    assert!(run.message.is_empty());
    case.queue_batch(runs).unwrap();
    assert!(
        quarantine::passive_runs(&case.directory, &case.document)
            .unwrap()
            .is_empty()
    );
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(outcome.status.has_results(), "{}", outcome.message);
    case.finish(&run.id, &outcome).unwrap();
    (run, outcome)
}

#[test]
fn passive_isolation_backfills_without_a_scan_and_refreshes_only_when_sources_change() {
    let (_temp, mut case, engine) = fixture();
    assert!(
        quarantine::passive_runs(&case.directory, &case.document)
            .unwrap()
            .is_empty()
    );
    scan(&mut case, &engine);
    let source = dump(&mut case, &engine, 0, "0x2000", None);
    let output = case.run_dir(&source.id).join("file.isolated.dat");
    extracted_files::block_artifact(
        &output,
        "Windows Defender isolated recovered output (os error 225)",
    )
    .unwrap();
    let (first, outcome) = passive(&mut case);
    let rows = outcome.table.unwrap().rows;
    let local = rows
        .iter()
        .find(|r| r.text("Scope") == "Local computer")
        .unwrap();
    assert_eq!(local.text("Original path"), ORIGINAL);
    assert!(local.text("Sources").contains(&source.id));
    assert!(
        quarantine::passive_runs(&case.directory, &case.document)
            .unwrap()
            .is_empty()
    );
    let directory = case.directory.clone();
    drop(case);
    let mut case = Case::open(&directory).unwrap();
    assert!(
        quarantine::passive_runs(&case.directory, &case.document)
            .unwrap()
            .is_empty()
    );
    save(
        &mut case,
        &engine,
        0,
        "windows.pslist.PsList",
        vec![],
        json!([{"PID":100,"ImageFileName":"payload.exe"}]),
    );
    let (second, outcome) = passive(&mut case);
    assert_ne!(first.arguments, second.arguments);
    assert!(
        outcome
            .table
            .unwrap()
            .rows
            .iter()
            .any(|r| r.text("Scope") == "Local computer" && r.text("PID") == "100")
    );
    extracted_files::block_artifact(
        &case.run_dir(&source.id).join("file.second.dat"),
        "output unavailable",
    )
    .unwrap();
    fs::remove_file(&case.document.evidence[0].path).unwrap();
    let (_, outcome) = passive(&mut case);
    assert_eq!(
        outcome
            .table
            .unwrap()
            .rows
            .iter()
            .filter(|r| r.text("Scope") == "Local computer")
            .count(),
        2
    );
}

#[test]
fn antivirus_interrupted_scans_without_output_rows_become_passive_leads() {
    let (_temp, mut case, engine) = fixture();
    for (plugin, status, message) in [
        (
            "windows.pslist.PsList",
            RunStatus::Failed,
            "Windows Defender: file contains a virus (os error 225)",
        ),
        (
            "windows.filescan.FileScan",
            RunStatus::Cancelled,
            "Antivirus quarantined a generated file",
        ),
        (
            "windows.handles.Handles",
            RunStatus::Interrupted,
            "Operation failed (os error 226)",
        ),
        (
            "windows.cmdline.CmdLine",
            RunStatus::Failed,
            "Access is denied (os error 5)",
        ),
    ] {
        let run = engine
            .prepare(
                &case.document.evidence[0],
                plugin,
                vec![],
                &case.directory.join("analyses"),
            )
            .unwrap();
        case.queue(run.clone()).unwrap();
        case.finish(
            &run.id,
            &Outcome {
                status,
                exit_code: Some(1),
                message: message.into(),
                table: None,
            },
        )
        .unwrap();
    }
    let other = engine
        .prepare(
            &case.document.evidence[1],
            "windows.pslist.PsList",
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(other.clone()).unwrap();
    case.finish(
        &other.id,
        &Outcome {
            status: RunStatus::Failed,
            exit_code: Some(1),
            message: "ordinary error".into(),
            table: None,
        },
    )
    .unwrap();
    let (_, outcome) = passive(&mut case);
    let rows = outcome.table.unwrap().rows;
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|r| r.text("Evidence status") == "Antivirus interruption reported")
    );
    assert!(
        rows.iter()
            .all(|r| r.text("Filename") == "Target not recorded"
                && r.text("Original path").is_empty())
    );
    assert!(
        !rows
            .iter()
            .any(|r| r.text("Source analysis") == "windows.cmdline.CmdLine")
    );
    assert!(!rows.iter().any(|r| r.text("Sources").contains(&other.id)));
}

#[test]
fn passive_snapshots_preserve_manual_capture_findings_and_do_not_queue_engine_work() {
    let (_temp, mut case, engine) = fixture();
    scan(&mut case, &engine);
    dump(&mut case, &engine, 0, "0x1000", Some(METADATA));
    execute(&mut case);
    let source = dump(&mut case, &engine, 0, "0x2000", None);
    extracted_files::block_artifact(
        &case.run_dir(&source.id).join("file.blocked.dat"),
        "unavailable",
    )
    .unwrap();
    let (_, outcome) = passive(&mut case);
    let rows = outcome.table.unwrap().rows;
    assert!(
        rows.iter()
            .any(|r| r.text("Evidence status").starts_with("Confirmed Defender"))
    );
    assert!(rows.iter().any(|r| r.text("Scope") == "Local computer"));
    assert!(
        !case
            .document
            .runs
            .iter()
            .any(|r| matches!(r.status, RunStatus::Queued | RunStatus::Running))
    );
    // A later explicit collection retains its normal deferred extraction workflow.
    let mut draft = AnalysisDraft::new(&case.document.evidence[0]);
    draft.selected.insert(analysis::QUARANTINE.into());
    assert_eq!(
        draft
            .prepare_in_case(&engine, &case.document.evidence[0], &case)
            .unwrap()
            .last()
            .unwrap()
            .message,
        quarantine::PENDING
    );
}

#[test]
fn passive_updates_take_an_available_slot_without_waiting_for_unrelated_queued_scans() {
    let (_temp, mut case, engine) = fixture();
    let source = dump(&mut case, &engine, 0, "0x2000", None);
    extracted_files::block_artifact(
        &case.run_dir(&source.id).join("file.blocked.dat"),
        "unavailable",
    )
    .unwrap();
    let passive = quarantine::passive_runs(&case.directory, &case.document)
        .unwrap()
        .remove(0);
    let mut running = source.clone();
    running.status = RunStatus::Running;
    let mut queued = source;
    queued.id = uuid::Uuid::new_v4().to_string();
    queued.status = RunStatus::Queued;
    assert_eq!(
        analyses::next_queued_run(&[running, queued, passive], NonZeroUsize::new(2).unwrap()),
        Some(2)
    );
}

#[test]
fn definitive_antivirus_io_errors_record_non_dumpfiles_targets_even_if_the_path_still_exists() {
    let (_temp, mut case, engine) = fixture();
    let source = save(
        &mut case,
        &engine,
        0,
        "windows.pslist.PsList",
        vec![],
        json!([]),
    );
    let path = case.run_dir(&source.id).join("pid.100.dmp");
    fs::create_dir_all(case.run_dir(&source.id)).unwrap();
    fs::write(&path, b"Synthetic content").unwrap();
    extracted_files::block_artifact(&path, "Antivirus rejected read (os error 225)").unwrap();
    let (_, outcome) = passive(&mut case);
    let table = outcome.table.unwrap();
    let row = table
        .rows
        .iter()
        .find(|r| r.text("Local output").ends_with("pid.100.dmp"))
        .unwrap();
    assert_eq!(row.text("Source analysis"), "windows.pslist.PsList");
    assert!(row.text("Blocked reason").contains("225"));
}
