use std::{fs, num::NonZeroUsize, sync::atomic::AtomicBool};
use volgui::{
    analyses::{self, AnalysisDraft},
    analysis::{self, downloads, quarantine},
    artifacts::OperatingSystem,
    case::{Case, Evidence, Run, RunStatus},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn fixture() -> (tempfile::TempDir, Case, Installation) {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("memory.raw");
    fs::write(&image, b"investigation prerequisites").unwrap();
    let mut evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    evidence.operating_system = OperatingSystem::Windows;
    let mut case = Case::create(&temp.path().join("case"), "Prerequisites").unwrap();
    case.add_evidence(evidence).unwrap();
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: downloads::SOURCES
            .iter()
            .chain(quarantine::SOURCES)
            .map(|id| Plugin {
                id: (*id).into(),
                description: String::new(),
            })
            .collect(),
    };
    (temp, case, engine)
}

fn finish(case: &mut Case, run: &Run) {
    case.finish(
        &run.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(Table::parse("[]").unwrap()),
        },
    )
    .unwrap();
}

#[test]
fn queue_adds_all_missing_inputs_once_before_both_reports() {
    let (_temp, mut case, engine) = fixture();
    let evidence = case.document.evidence[0].clone();
    let mut draft = AnalysisDraft::new(&evidence);
    draft
        .selected
        .extend([analysis::DOWNLOADS.into(), analysis::QUARANTINE.into()]);
    let runs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    for plugin in downloads::SOURCES.iter().chain(quarantine::SOURCES) {
        assert_eq!(runs.iter().filter(|r| r.plugin == *plugin).count(), 1);
    }
    for (index, report) in runs
        .iter()
        .enumerate()
        .filter(|(_, r)| analysis::is_native(&r.plugin))
    {
        let sources = if report.plugin == analysis::DOWNLOADS {
            downloads::SOURCES
        } else {
            quarantine::SOURCES
        };
        assert!(
            analysis::missing_source_inventories(&runs[..index], &evidence.id, sources, true)
                .is_empty()
        );
    }
    case.queue_batch(runs).unwrap();
    // Repeated requests reuse inputs already queued rather than duplicating them.
    let next = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    assert_eq!(next.len(), 2);
    assert!(next.iter().all(|r| analysis::is_native(&r.plugin)));
}

#[test]
fn queue_replaces_failed_filtered_and_wrong_evidence_inputs_but_reuses_successes() {
    for plugin in [analysis::DOWNLOADS, analysis::QUARANTINE] {
        let (_temp, mut case, engine) = fixture();
        let evidence = case.document.evidence[0].clone();
        let sources = if plugin == analysis::DOWNLOADS {
            downloads::SOURCES
        } else {
            quarantine::SOURCES
        };
        let mut draft = AnalysisDraft::new(&evidence);
        draft.selected.insert(plugin.into());
        case.queue_batch(draft.prepare_in_case(&engine, &evidence, &case).unwrap())
            .unwrap();
        case.document.runs.pop();
        for run in &mut case.document.runs {
            run.status = RunStatus::Completed;
        }
        for status in [
            RunStatus::Failed,
            RunStatus::Cancelled,
            RunStatus::Interrupted,
        ] {
            case.document.runs[0].status = status;
            let runs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
            assert_eq!(runs.len(), 2);
            assert_eq!(runs[0].plugin, sources[0]);
            assert!(runs[0].arguments.is_empty());
        }
        case.document.runs[0].status = RunStatus::Completed;
        case.document.runs[0].arguments = vec!["--pid".into(), "42".into()];
        assert_eq!(
            draft
                .prepare_in_case(&engine, &evidence, &case)
                .unwrap()
                .len(),
            2
        );
        case.document.runs[0].arguments.clear();
        case.document.runs[0].evidence_id = "other capture".into();
        assert_eq!(
            draft
                .prepare_in_case(&engine, &evidence, &case)
                .unwrap()
                .len(),
            2
        );
        case.document.runs[0].evidence_id = evidence.id.clone();
        for status in [
            RunStatus::Completed,
            RunStatus::Warning,
            RunStatus::Queued,
            RunStatus::Running,
        ] {
            case.document.runs[0].status = status;
            assert_eq!(
                draft
                    .prepare_in_case(&engine, &evidence, &case)
                    .unwrap()
                    .len(),
                1
            );
        }
        // Unsupported prerequisites must not be silently skipped.
        case.document.runs[0].status = RunStatus::Failed;
        let mut unsupported = engine.clone();
        unsupported.plugins.retain(|p| p.id != sources[0]);
        assert!(
            draft
                .prepare_in_case(&unsupported, &evidence, &case)
                .is_err()
        );
    }
}

#[test]
fn failed_prerequisites_fail_reports_and_later_results_cannot_supply_inputs() {
    for plugin in [analysis::DOWNLOADS, analysis::QUARANTINE] {
        let (_temp, mut case, engine) = fixture();
        let evidence = case.document.evidence[0].clone();
        let mut draft = AnalysisDraft::new(&evidence);
        draft.selected.insert(plugin.into());
        let runs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
        let report = runs.last().unwrap().clone();
        case.queue_batch(runs.clone()).unwrap();
        for run in &runs[..runs.len() - 1] {
            finish(&mut case, run);
        }
        let later = engine
            .prepare(
                &evidence,
                &runs[0].plugin,
                vec![],
                &case.directory.join("analyses"),
            )
            .unwrap();
        case.queue(later.clone()).unwrap();
        finish(&mut case, &later);
        for status in [
            RunStatus::Failed,
            RunStatus::Cancelled,
            RunStatus::Interrupted,
        ] {
            case.document.runs[0].status = status;
            // With no active jobs the report is ready, even when an input failed.
            assert_eq!(
                analyses::next_queued_run(&case.document.runs, NonZeroUsize::new(2).unwrap()),
                Some(runs.len() - 1)
            );
            let prepared = if plugin == analysis::DOWNLOADS {
                analyses::prepare_download_recovery(&case, &engine, &report)
            } else {
                analyses::prepare_quarantine_recovery(&case, &engine, &report)
            };
            assert!(prepared.unwrap_err().contains("Missing source inventories"));
            let outcome = analysis::execute(
                &case.directory,
                &case.document,
                &report,
                &AtomicBool::new(false),
                |_| {},
            );
            assert_eq!(outcome.status, RunStatus::Failed, "{}", outcome.message);
            assert!(outcome.message.contains(&runs[0].plugin));
            assert!(outcome.table.is_none());
        }
    }
}

#[test]
fn cancelled_jobs_retry_and_downloads_without_an_engine_do_not_wait_for_recovery() {
    let (_temp, mut case, engine) = fixture();
    let evidence = case.document.evidence[0].clone();
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::DOWNLOADS.into());
    let runs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    case.queue_batch(runs.clone()).unwrap();
    for run in &runs[..runs.len() - 1] {
        finish(&mut case, run);
    }
    let report = runs.last().unwrap();
    case.document.runs.last_mut().unwrap().status = RunStatus::Cancelled;
    analyses::queue_retries_with_engine(&mut case, None, std::slice::from_ref(&report.id)).unwrap();
    let retry = case.document.runs.last().unwrap().clone();
    assert!(retry.message.is_empty());
    assert_ne!(retry.id, report.id);
    assert_eq!(
        analyses::next_queued_run(&case.document.runs, NonZeroUsize::new(2).unwrap()),
        Some(case.document.runs.len() - 1)
    );
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &retry,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(outcome.status.has_results(), "{}", outcome.message);
    assert_eq!(
        case.document.runs[runs.len() - 1].status,
        RunStatus::Cancelled
    );

    finish(&mut case, &retry);
    let original = engine
        .prepare(
            &evidence,
            downloads::SOURCES[0],
            vec!["--pid".into(), "42".into()],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(original.clone()).unwrap();
    case.document.runs.last_mut().unwrap().status = RunStatus::Cancelled;
    analyses::queue_retries(&mut case, &engine, std::slice::from_ref(&original.id)).unwrap();
    let retry = case.document.runs.last().unwrap();
    assert_eq!(retry.status, RunStatus::Queued);
    assert_eq!(retry.arguments, original.arguments);
    assert_ne!(retry.id, original.id);
}
