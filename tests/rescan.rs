use std::{fs, io::Read, sync::atomic::AtomicBool};
use volgui::{
    analyses, analysis,
    artifacts::OperatingSystem,
    case::{Case, CaseSnapshot, Evidence, Run, RunStatus},
    database, object_store,
    results::{Query, ResultStore},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn fixture() -> (tempfile::TempDir, Case, Installation) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Rescan fixture").unwrap();
    // An acquisition inside the case directory must also survive a rebuild.
    for path in [
        case.directory.join("first.raw"),
        temp.path().join("second.raw"),
    ] {
        fs::write(&path, b"synthetic rescan acquisition").unwrap();
        let mut evidence = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap();
        evidence.operating_system = OperatingSystem::Windows;
        case.add_evidence(evidence).unwrap();
    }
    let mut plugins = vec![
        "windows.pslist.PsList",
        "windows.cmdline.CmdLine",
        "windows.filescan.FileScan",
        "windows.handles.Handles",
        analysis::application::MEMMAP,
        analysis::application::VADINFO,
        volgui::extracted_files::DUMP_FILES,
    ];
    plugins.extend(analysis::network::SOURCES.iter().copied());
    plugins.extend(analysis::downloads::SOURCES.iter().copied());
    plugins.extend(analysis::quarantine::SOURCES.iter().copied());
    plugins.sort_unstable();
    plugins.dedup();
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "rescan fixture".into(),
        plugins: plugins
            .into_iter()
            .map(|id| Plugin {
                id: id.into(),
                description: String::new(),
            })
            .collect(),
    };
    (temp, case, engine)
}

fn completed(
    case: &mut Case,
    engine: &Installation,
    evidence: usize,
    plugin: &str,
    arguments: &[&str],
) -> Run {
    let evidence = &case.document.evidence[evidence];
    let arguments = arguments.iter().map(|s| s.to_string()).collect();
    let run = if analysis::is_native(plugin) {
        analysis::prepare(evidence, plugin, arguments).unwrap()
    } else {
        engine
            .prepare(
                evidence,
                plugin,
                arguments,
                &case.directory.join("analyses"),
            )
            .unwrap()
    };
    case.queue(run.clone()).unwrap();
    case.document.runs.last_mut().unwrap().status = RunStatus::Completed;
    case.save().unwrap();
    run
}

#[test]
fn rescan_replaces_results_and_retains_a_reopenable_backup_and_binary_deduplication() {
    let (_temp, mut case, engine) = fixture();
    case.document.created_at = "2020-01-02T03:04:05Z".into();
    database::connect(&case.directory)
        .unwrap()
        .execute(
            "UPDATE case_meta SET created_at=?1",
            [&case.document.created_at],
        )
        .unwrap();
    let run = completed(
        &mut case,
        &engine,
        0,
        analysis::application::MEMMAP,
        &["--pid", "40"],
    );
    let capture = case.run_dir(&run.id);
    fs::create_dir_all(&capture).unwrap();
    fs::write(capture.join("memory.dmp"), b"recoverable memory bytes").unwrap();
    case.finish(
        &run.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: "fixture complete".into(),
            table: Some(Table::parse(r#"[{"PID":40,"ImageFileName":"fixture.exe"}]"#).unwrap()),
        },
    )
    .unwrap();
    case.annotate(&run.id, 0, true, "Keep this annotation".into())
        .unwrap();
    completed(
        &mut case,
        &engine,
        0,
        analysis::application::MEMMAP,
        &["--pid", "40"],
    );
    completed(
        &mut case,
        &engine,
        0,
        analysis::application::MEMMAP,
        &["--pid", "50"],
    );
    completed(
        &mut case,
        &engine,
        1,
        analysis::application::MEMMAP,
        &["--pid", "40"],
    );
    case.document.runs[1].status = RunStatus::Failed;
    case.document.runs[2].status = RunStatus::Cancelled;
    case.document.runs[3].status = RunStatus::Interrupted;
    case.document.cleared_queue_runs.insert(run.id.clone());
    case.save().unwrap();
    let original = serde_json::to_value(&case.document).unwrap();
    let root = case.directory.clone();
    let old_ids: Vec<_> = case
        .document
        .runs
        .iter()
        .map(|run| run.id.clone())
        .collect();
    case.enable_background_saves().unwrap();
    case.annotate(&run.id, 0, true, "Latest background annotation".into())
        .unwrap();

    let backup_path = case.rescan(&engine, &AtomicBool::new(false)).unwrap();
    assert!(backup_path.starts_with(root.join("backups")));
    assert_eq!(case.directory, root);
    assert_eq!(case.document.name, original["name"]);
    assert_eq!(case.document.created_at, original["created_at"]);
    assert_eq!(
        serde_json::to_value(&case.document.evidence).unwrap(),
        original["evidence"]
    );
    assert_eq!(case.document.runs.len(), 3);
    assert!(case.document.annotations.is_empty());
    assert!(case.document.cleared_queue_runs.is_empty());
    for run in &case.document.runs {
        assert!(!old_ids.contains(&run.id));
        assert_eq!(run.status, RunStatus::Queued);
        assert_eq!(run.row_count, 0);
        assert!(run.started_at.is_none() && run.finished_at.is_none());
        let output = run.command.windows(2).find(|pair| pair[0] == "-o").unwrap();
        assert_eq!(output[1], case.run_dir(&run.id).display().to_string());
    }
    let db = database::connect(&root).unwrap();
    for table in [
        "scans",
        "observations",
        "run_observations",
        "record_search",
        "entities",
        "annotations",
        "analysis_outputs",
    ] {
        assert_eq!(
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "{table}"
        );
    }
    assert!(
        db.query_row("SELECT COUNT(*) FROM binary_chunks", [], |row| row
            .get::<_, i64>(0))
            .unwrap()
            > 0
    );
    assert!(
        Case::open(&root).is_err(),
        "rebuild must retain the case lock"
    );
    let backup = Case::open(&backup_path).unwrap();
    assert_eq!(backup.document.runs.len(), 4);
    assert_eq!(backup.results(&run.id).unwrap().rows.len(), 1);
    assert_eq!(
        backup.annotation(&run.id, 0).unwrap().note,
        "Latest background annotation"
    );
    let mut bytes = Vec::new();
    object_store::open(&backup.run_dir(&run.id).join("memory.dmp"))
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"recoverable memory bytes");
    assert_eq!(
        fs::read(&case.document.evidence[0].path).unwrap(),
        b"synthetic rescan acquisition"
    );

    // Subsequent ingestion uses the rebuilt schema and the existing chunk pack.
    let replay = case.document.runs[0].clone();
    fs::create_dir_all(case.run_dir(&replay.id)).unwrap();
    fs::write(
        case.run_dir(&replay.id).join("memory.dmp"),
        b"recoverable memory bytes",
    )
    .unwrap();
    let pack = root.join("objects/chunks.pack");
    let pack_length = fs::metadata(&pack).unwrap().len();
    case.finish(
        &replay.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(Table::parse(r#"[{"PID":40,"ImageFileName":"rescanned.exe"}]"#).unwrap()),
        },
    )
    .unwrap();
    assert_eq!(fs::metadata(pack).unwrap().len(), pack_length);
    assert_eq!(
        ResultStore::at(&root)
            .query(&Query {
                runs: vec![replay.id.clone()],
                ..Default::default()
            })
            .unwrap()
            .ids
            .len(),
        1
    );
    assert_eq!(
        CaseSnapshot::load(&root).unwrap().created_at,
        case.document.created_at
    );
}

#[test]
fn rescan_reprepares_native_jobs_with_current_dependencies_and_without_old_pinned_ids() {
    let (_temp, mut case, engine) = fixture();
    for plugin in [
        "windows.pslist.PsList",
        "windows.cmdline.CmdLine",
        "windows.filescan.FileScan",
    ] {
        completed(&mut case, &engine, 0, plugin, &[]);
    }
    completed(
        &mut case,
        &engine,
        0,
        analysis::APPLICATION,
        &[
            "--pid",
            "40",
            "--contains",
            "draft text",
            "--source-run",
            "old-dump",
            "--inventory-run",
            "old-inventory",
        ],
    );
    completed(&mut case, &engine, 0, analysis::BROWSER, &[]);
    completed(&mut case, &engine, 0, analysis::FILES, &["--physical"]);
    completed(&mut case, &engine, 0, analysis::NETWORK, &[]);
    completed(&mut case, &engine, 0, analysis::DOWNLOADS, &[]);
    completed(&mut case, &engine, 0, analysis::QUARANTINE, &[]);
    completed(&mut case, &engine, 1, analysis::STRINGS, &["needle"]);
    case.rescan(&engine, &AtomicBool::new(false)).unwrap();

    let application = case
        .document
        .runs
        .iter()
        .find(|r| r.plugin == analysis::APPLICATION)
        .unwrap();
    assert_eq!(
        application.arguments,
        ["--pid", "40", "--contains", "draft text"]
    );
    assert_eq!(application.message, analyses::APPLICATION_RECOVERY_PENDING);
    for (plugin, pending) in [
        (analysis::BROWSER, analyses::BROWSER_RECOVERY_PENDING),
        (analysis::FILES, analysis::files::PENDING),
        (analysis::DOWNLOADS, analysis::downloads::PENDING),
        (analysis::QUARANTINE, analysis::quarantine::PENDING),
    ] {
        assert_eq!(
            case.document
                .runs
                .iter()
                .find(|r| r.plugin == plugin)
                .unwrap()
                .message,
            pending
        );
    }
    assert_eq!(
        case.document
            .runs
            .iter()
            .find(|r| r.plugin == analysis::FILES)
            .unwrap()
            .arguments,
        ["--physical"]
    );
    assert_eq!(
        case.document
            .runs
            .iter()
            .find(|r| r.plugin == analysis::STRINGS)
            .unwrap()
            .arguments,
        ["needle"]
    );
    let network = case
        .document
        .runs
        .iter()
        .position(|r| r.plugin == analysis::NETWORK)
        .unwrap();
    for plugin in analysis::network::SOURCES {
        assert!(
            case.document.runs[..network]
                .iter()
                .any(|r| r.plugin == *plugin && r.arguments.is_empty())
        );
    }
    for run in &case.document.runs {
        assert_eq!(run.status, RunStatus::Queued);
        if !analysis::is_native(&run.plugin) {
            assert_eq!(
                run.command.windows(2).find(|p| p[0] == "-o").unwrap()[1],
                case.run_dir(&run.id).display().to_string()
            );
        }
    }
}

#[test]
fn rescan_preparation_errors_and_cancellation_preserve_the_current_case() {
    let (_temp, mut case, mut engine) = fixture();
    completed(&mut case, &engine, 0, "windows.pslist.PsList", &[]);
    let original = serde_json::to_value(&case.document).unwrap();
    assert!(
        case.rescan(&engine, &AtomicBool::new(true))
            .unwrap_err()
            .contains("cancelled")
    );
    assert_eq!(serde_json::to_value(&case.document).unwrap(), original);
    engine.plugins.clear();
    assert!(
        case.rescan(&engine, &AtomicBool::new(false))
            .unwrap_err()
            .contains("windows.pslist.PsList")
    );
    assert_eq!(serde_json::to_value(&case.document).unwrap(), original);
    assert_eq!(
        serde_json::to_value(CaseSnapshot::load(&case.directory).unwrap()).unwrap(),
        original
    );
    assert!(!case.directory.join("backups").exists());
}

#[test]
fn rescan_requires_an_idle_case_with_previous_scans() {
    let (_temp, mut case, engine) = fixture();
    assert!(
        case.rescan(&engine, &AtomicBool::new(false))
            .unwrap_err()
            .contains("no previous analyses")
    );
    let run = completed(&mut case, &engine, 0, "windows.pslist.PsList", &[]);
    for status in [RunStatus::Running, RunStatus::Queued] {
        case.document.runs[0].status = status;
        assert!(
            case.rescan(&engine, &AtomicBool::new(false))
                .unwrap_err()
                .contains("Finish or cancel")
        );
        assert_eq!(case.document.runs[0].id, run.id);
    }
}

#[test]
fn backup_failure_leaves_the_original_results_available() {
    let (_temp, mut case, engine) = fixture();
    let run = completed(&mut case, &engine, 0, "windows.pslist.PsList", &[]);
    // A malformed managed directory must stop publication, not skip the backup.
    fs::write(case.directory.join("objects"), b"not a directory").unwrap();
    assert!(case.rescan(&engine, &AtomicBool::new(false)).is_err());
    assert_eq!(case.document.runs[0].id, run.id);
    assert_eq!(
        CaseSnapshot::load(&case.directory).unwrap().runs[0].id,
        run.id
    );
    assert_eq!(
        fs::read_dir(case.directory.join("backups"))
            .unwrap()
            .count(),
        0
    );
}
