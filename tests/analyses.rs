// Checks analyses behavior.
use std::{fs, sync::atomic::AtomicBool};
use volgui::{
    analyses::{AnalysisDraft, basic_label, chooser_plugins, queue_retries},
    artifacts::OperatingSystem,
    case::{Case, CaseDocument, Evidence, MANIFEST, QueueClearScope, RunStatus},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn plugin(id: &str) -> Plugin {
    Plugin {
        id: id.into(),
        description: "Test plugin".into(),
    }
}

#[test]
fn shift_selection_uses_visible_order_in_both_directions_and_can_clear_ranges() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic selection fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut draft = AnalysisDraft::new(&evidence);
    let visible: Vec<String> = ["d", "b", "a", "c", "e"].map(String::from).into();

    draft.select("d", true, false, &visible);
    draft.select("b", true, false, &visible);
    draft.select("c", true, true, &visible);
    assert_eq!(
        draft.selected,
        ["a", "b", "c", "d"].map(String::from).into()
    );
    draft.select("a", false, true, &visible);
    assert_eq!(draft.selected, ["c", "d"].map(String::from).into());

    draft.select("e", true, false, &visible);
    draft.select("a", true, true, &visible);
    assert_eq!(
        draft.selected,
        ["a", "c", "d", "e"].map(String::from).into()
    );
}

#[test]
fn shift_selection_respects_filters_and_separate_evidence_drafts() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic selection fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut draft = AnalysisDraft::new(&evidence);
    let all = ["a", "b", "c", "d"].map(String::from);
    let filtered = ["b", "d"].map(String::from);
    draft.select("b", true, false, &all);
    draft.select("d", true, true, &filtered);
    assert_eq!(draft.selected, ["b", "d"].map(String::from).into());

    let mut other = AnalysisDraft::new(&evidence);
    other.select("d", true, true, &all);
    assert_eq!(other.selected, [String::from("d")].into());

    // A hidden anchor falls back to the clicked checkbox, without touching hidden rows.
    draft.select("a", true, false, &all);
    draft.select("d", false, true, &filtered);
    assert_eq!(draft.selected, ["a", "b"].map(String::from).into());
}

#[test]
fn basic_catalog_includes_the_requested_tasks_and_sorts_before_extended() {
    let requested = [
        "windows.info.Info",
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.psscan.PsScan",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        "windows.dlllist.DllList",
        "windows.filescan.FileScan",
        "windows.dumpfiles.DumpFiles",
        "windows.handles.Handles",
        "windows.registry.hivelist.HiveList",
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.bash.Bash",
        "mac.pslist.PsList",
        "mac.bash.Bash",
    ];
    assert!(requested.iter().all(|id| basic_label(id).is_some()));
    let mut plugins: Vec<_> = requested.iter().map(|id| plugin(id)).collect();
    plugins.push(plugin("frameworkinfo.FrameworkInfo"));
    plugins.push(plugin("windows.registry.printkey.PrintKey"));
    let basic = chooser_plugins(&plugins, OperatingSystem::Windows, false, "");
    assert_eq!(basic.len(), 11);
    assert!(basic.iter().all(|p| p.id.starts_with("windows.")));
    let full = chooser_plugins(&plugins, OperatingSystem::Windows, true, "");
    assert_eq!(full.len(), 13);
    assert!(full[..11].iter().all(|p| basic_label(&p.id).is_some()));
    assert!(full[11..].iter().all(|p| basic_label(&p.id).is_none()));
    assert_eq!(
        chooser_plugins(&plugins, OperatingSystem::Windows, false, "dump files")[0].id,
        "windows.dumpfiles.DumpFiles"
    );
    assert_eq!(
        chooser_plugins(&plugins, OperatingSystem::Windows, false, "registry hives").len(),
        1
    );
    assert_eq!(
        chooser_plugins(&plugins, OperatingSystem::Windows, false, "FrameworkInfo").len(),
        0
    );
}

#[test]
fn retries_preserve_options_and_history_and_queue_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic retry fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Retry test").unwrap();
    case.add_evidence(evidence.clone()).unwrap();
    let engine = Installation {
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: vec![plugin("windows.dumpfiles.DumpFiles")],
    };
    let mut failed = engine
        .prepare(
            &evidence,
            "windows.dumpfiles.DumpFiles",
            vec!["--pid".into(), "40".into()],
            &case.directory.join("analyses"),
        )
        .unwrap();
    let mut interrupted = failed.clone();
    interrupted.id = uuid::Uuid::new_v4().to_string();
    let mut completed = failed.clone();
    completed.id = uuid::Uuid::new_v4().to_string();
    case.queue_batch(vec![failed.clone(), interrupted.clone(), completed.clone()])
        .unwrap();
    failed.status = RunStatus::Failed;
    interrupted.status = RunStatus::Interrupted;
    completed.status = RunStatus::Completed;
    case.document.runs = vec![failed.clone(), interrupted.clone(), completed.clone()];
    case.save().unwrap();
    let ids = [failed.id.clone(), interrupted.id.clone()];

    // A bad request must not leave the valid first retry queued.
    for invalid in [completed.id.clone(), "missing".into()] {
        assert!(queue_retries(&mut case, &engine, &[ids[0].clone(), invalid]).is_err());
        assert_eq!(case.document.runs.len(), 3);
    }
    let mut unavailable = engine.clone();
    unavailable.plugins.clear();
    assert!(queue_retries(&mut case, &unavailable, &ids).is_err());
    assert_eq!(case.document.runs.len(), 3);

    let manifest = case.directory.join(MANIFEST);
    let saved = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(queue_retries(&mut case, &engine, &ids).is_err());
    assert_eq!(case.document.runs.len(), 3);
    fs::remove_dir(&manifest).unwrap();
    fs::write(&manifest, saved).unwrap();

    assert_eq!(queue_retries(&mut case, &engine, &ids).unwrap(), 2);
    assert_eq!(case.document.runs.len(), 5);
    assert_eq!(case.document.runs[0].status, RunStatus::Failed);
    assert_eq!(case.document.runs[1].status, RunStatus::Interrupted);
    assert_eq!(case.document.runs[2].status, RunStatus::Completed);
    for run in &case.document.runs[3..] {
        assert!(!ids.contains(&run.id));
        assert_eq!(run.status, RunStatus::Queued);
        assert_eq!(run.evidence_id, evidence.id);
        assert_eq!(run.plugin, failed.plugin);
        assert_eq!(run.arguments, failed.arguments);
        assert!(run.command.iter().any(|arg| arg.contains(&run.id)));
    }
    let directory = case.directory.clone();
    drop(case);
    let reopened = Case::open(&directory).unwrap();
    assert_eq!(reopened.document.runs.len(), 5);
}

#[test]
fn clearing_queue_preserves_active_jobs_history_and_results_and_survives_reopening() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic queue fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Queue cleanup test").unwrap();
    case.add_evidence(evidence.clone()).unwrap();
    let engine = Installation {
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: vec![plugin("windows.pslist.PsList")],
    };
    let runs = (0..6)
        .map(|_| {
            engine
                .prepare(
                    &evidence,
                    "windows.pslist.PsList",
                    vec![],
                    &case.directory.join("analyses"),
                )
                .unwrap()
        })
        .collect();
    case.queue_batch(runs).unwrap();
    let completed_id = case.document.runs[0].id.clone();
    case.finish(
        &completed_id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(Table::parse(r#"[{"PID":40}]"#).unwrap()),
        },
    )
    .unwrap();
    let statuses = [
        RunStatus::Completed,
        RunStatus::Cancelled,
        RunStatus::Failed,
        RunStatus::Interrupted,
        RunStatus::Queued,
        RunStatus::Running,
    ];
    for (run, status) in case.document.runs.iter_mut().zip(statuses) {
        run.status = status;
    }
    case.save().unwrap();
    let manifest = case.directory.join(MANIFEST);
    let legacy: CaseDocument = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert!(legacy.cleared_queue_runs.is_empty());
    assert_eq!(legacy.queue_runs().count(), 6);

    assert_eq!(case.clear_queue(QueueClearScope::Completed).unwrap(), 2);
    assert_eq!(case.clear_queue(QueueClearScope::Completed).unwrap(), 0);
    assert_eq!(
        case.document
            .queue_runs()
            .map(|r| r.status)
            .collect::<Vec<_>>(),
        statuses[2..]
    );

    // A failed manifest save must leave both the queue and existing dismissals intact.
    let saved = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(case.clear_queue(QueueClearScope::Finished).is_err());
    assert_eq!(case.document.queue_runs().count(), 4);
    assert_eq!(case.document.cleared_queue_runs.len(), 2);
    fs::remove_dir(&manifest).unwrap();
    fs::write(&manifest, saved).unwrap();

    assert_eq!(case.clear_queue(QueueClearScope::Finished).unwrap(), 2);
    assert_eq!(case.clear_queue(QueueClearScope::Finished).unwrap(), 0);
    assert_eq!(
        case.document
            .queue_runs()
            .map(|r| r.status)
            .collect::<Vec<_>>(),
        statuses[4..]
    );
    assert_eq!(case.document.runs.len(), 6);
    assert_eq!(case.results(&completed_id).unwrap().rows.len(), 1);
    let directory = case.directory.clone();
    let failed_id = case.document.runs[2].id.clone();
    drop(case);
    let mut reopened = Case::open(&directory).unwrap();
    assert_eq!(reopened.document.queue_runs().count(), 2);
    assert_eq!(reopened.document.runs.len(), 6);
    assert_eq!(reopened.results(&completed_id).unwrap().rows.len(), 1);
    // Retrying a cleared run from History creates a visible new attempt.
    queue_retries(&mut reopened, &engine, &[failed_id]).unwrap();
    assert_eq!(reopened.document.queue_runs().count(), 3);
    assert_eq!(
        reopened.document.runs.last().unwrap().status,
        RunStatus::Queued
    );
}

#[test]
fn batch_selection_preserves_individual_options_and_is_saved_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic test evidence").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Batch test").unwrap();
    case.add_evidence(evidence.clone()).unwrap();
    let engine = Installation {
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: vec![
            plugin("windows.pslist.PsList"),
            plugin("windows.cmdline.CmdLine"),
            plugin("linux.pslist.PsList"),
            plugin("frameworkinfo.FrameworkInfo"),
        ],
    };
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.extend([
        "windows.pslist.PsList".into(),
        "windows.cmdline.CmdLine".into(),
    ]);
    draft
        .arguments
        .insert("windows.pslist.PsList".into(), "--pid 40".into());
    draft
        .arguments
        .insert("windows.cmdline.CmdLine".into(), "--pid 80".into());
    let runs = draft
        .prepare(&engine, &evidence, &case.directory.join("analyses"))
        .unwrap();
    assert_eq!(runs.len(), 2);
    assert!(
        runs.iter()
            .any(|r| r.plugin == "windows.pslist.PsList" && r.arguments == ["--pid", "40"])
    );
    assert!(
        runs.iter()
            .any(|r| r.plugin == "windows.cmdline.CmdLine" && r.arguments == ["--pid", "80"])
    );
    let mut invalid = runs.clone();
    invalid[1].id = invalid[0].id.clone();
    assert!(case.queue_batch(invalid).is_err());
    assert!(case.document.runs.is_empty());
    assert!(case.queue_batch(Vec::new()).is_err());
    let manifest = case.directory.join(MANIFEST);
    let saved = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(case.queue_batch(runs.clone()).is_err());
    assert!(case.document.runs.is_empty());
    fs::remove_dir(&manifest).unwrap();
    fs::write(&manifest, saved).unwrap();
    case.queue_batch(runs).unwrap();
    let directory = case.directory.clone();
    drop(case);
    assert_eq!(Case::open(&directory).unwrap().document.runs.len(), 2);

    draft.selected.insert("frameworkinfo.FrameworkInfo".into());
    draft.set_os(OperatingSystem::Linux);
    assert_eq!(
        draft.selected.iter().cloned().collect::<Vec<_>>(),
        vec!["frameworkinfo.FrameworkInfo"]
    );
    draft.selected.insert("linux.pslist.PsList".into());
    draft
        .arguments
        .insert("linux.pslist.PsList".into(), "--pid \"unterminated".into());
    assert!(
        draft
            .prepare(&engine, &evidence, &directory.join("analyses"))
            .is_err()
    );
    draft.arguments.remove("linux.pslist.PsList");
    draft.selected.insert("windows.pslist.PsList".into());
    assert!(
        draft
            .prepare(&engine, &evidence, &directory.join("analyses"))
            .is_err()
    );
}
