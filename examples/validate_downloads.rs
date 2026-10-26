//! Exercise the desktop download workflow in a separate case, optionally reusing inventories.
use std::{path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analyses::{self, AnalysisDraft},
    analysis,
    artifacts::OperatingSystem,
    case::{Case, CaseSnapshot, Evidence, RunStatus, now},
    results::{Query, ResultStore},
    settings::Settings,
    volatility::{Installation, Outcome, Table},
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let capture = PathBuf::from(
        args.next()
            .ok_or("Usage: validate_downloads <capture> <new-case> <engine> [source-case]")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify a new case directory")?);
    let executable = PathBuf::from(args.next().ok_or("Specify an engine")?);
    let source = args.next().map(PathBuf::from);
    let cancel = AtomicBool::new(false);
    let document = source
        .as_ref()
        .map(|path| CaseSnapshot::load(path))
        .transpose()?;
    let mut evidence = if let Some(document) = &document {
        let canonical = capture.canonicalize().map_err(|e| e.to_string())?;
        document
            .evidence
            .iter()
            .find(|e| e.path == canonical)
            .ok_or("Source case does not contain this capture")?
            .clone()
    } else {
        Evidence::inspect(&capture, &cancel, |_, _| {})?
    };
    evidence.check_metadata()?;
    evidence.operating_system = OperatingSystem::Windows;
    let mut case = Case::create(&output, "Download investigation validation")?;
    case.add_evidence(evidence.clone())?;
    if let (Some(source), Some(document)) = (&source, &document) {
        let store = ResultStore::at(source);
        for plugin in analysis::downloads::SOURCES {
            if let Some(run) = document.runs.iter().rev().find(|r| {
                r.evidence_id == evidence.id
                    && r.plugin == *plugin
                    && r.arguments.is_empty()
                    && r.status == RunStatus::Completed
            }) {
                let ids = store
                    .query(&Query {
                        runs: vec![run.id.clone()],
                        ..Default::default()
                    })?
                    .ids;
                let mut rows = Vec::new();
                for ids in ids.chunks(256) {
                    rows.extend(store.fetch(ids)?.into_iter().map(|r| r.record));
                }
                let table = Table {
                    columns: rows
                        .iter()
                        .flat_map(|r| r.fields.keys().cloned())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    rows,
                };
                let mut imported = run.clone();
                imported.status = RunStatus::Queued;
                case.queue(imported)?;
                case.finish(
                    &run.id,
                    &Outcome {
                        status: RunStatus::Completed,
                        exit_code: Some(0),
                        message: "Imported inventory for validation".into(),
                        table: Some(table),
                    },
                )?;
            }
        }
    }
    let engine = Installation::discover(
        Settings {
            executable,
            ..Default::default()
        },
        &cancel,
    )?;
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::DOWNLOADS.into());
    case.queue_batch(draft.prepare_in_case(&engine, &evidence, &case)?)?;
    while let Some(index) = case
        .document
        .runs
        .iter()
        .position(|r| r.status == RunStatus::Queued)
    {
        if case.document.runs[index].plugin == analysis::DOWNLOADS
            && case.document.runs[index].message == analysis::downloads::PENDING
        {
            let runs =
                analyses::prepare_download_recovery(&case, &engine, &case.document.runs[index])?;
            case.document.runs.splice(index..=index, runs);
            case.save()?;
            continue;
        }
        case.document.runs[index].status = RunStatus::Running;
        case.document.runs[index].started_at = Some(now());
        case.save()?;
        let run = case.document.runs[index].clone();
        eprintln!("Running {} {:?}", run.plugin, run.arguments);
        let outcome = if analysis::is_native(&run.plugin) {
            analysis::execute(&case.directory, &case.document, &run, &cancel, |s| {
                eprintln!("{s}")
            })
        } else {
            engine.execute(&run, &case.run_dir(&run.id), &cancel)
        };
        case.finish(&run.id, &outcome)?;
        eprintln!("{}: {}", run.plugin, outcome.status.label());
        if run.plugin == analysis::DOWNLOADS {
            if outcome.status != RunStatus::Completed {
                return Err(outcome.message);
            }
            let table = case.results(&run.id)?;
            std::fs::write(
                case.directory.join("downloads.csv"),
                table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
            )
            .map_err(|e| e.to_string())?;
            for row in &table.rows {
                if !row.text("PID").is_empty() {
                    println!(
                        "{} | {} | PID {} | {}:{} | {}",
                        row.text("URL"),
                        row.text("Filename"),
                        row.text("PID"),
                        row.text("Remote IP"),
                        row.text("Remote port"),
                        row.text("Execution evidence")
                    );
                }
            }
            println!("{}\nCase: {}", outcome.message, case.directory.display());
        }
    }
    Ok(())
}
