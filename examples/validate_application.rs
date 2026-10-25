//! Run the application's recovery queue in a separate case using a real capture.
use std::{path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analyses::{APPLICATION_RECOVERY_PENDING, AnalysisDraft, prepare_application_recovery},
    analysis,
    case::{Case, CaseSnapshot, RunStatus, now},
    results::ResultStore,
    settings::Settings,
    volatility::{Installation, Outcome},
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source = PathBuf::from(args.next().ok_or("Usage: validate_application <source-case> <new-case> <vol-executable> --pid PID [--contains text]")?);
    let output = PathBuf::from(args.next().ok_or("Specify a new case directory")?);
    let executable = PathBuf::from(args.next().ok_or("Specify the engine")?);
    let arguments: Vec<_> = args.map(|s| s.to_string_lossy().into_owned()).collect();
    let document = CaseSnapshot::load(&source)?;
    let evidence = document
        .evidence
        .first()
        .ok_or("Source case has no evidence")?
        .clone();
    evidence.check_metadata()?;
    let reuse =
        output.canonicalize().ok() == Some(source.canonicalize().map_err(|e| e.to_string())?);
    let mut case = if reuse {
        Case::open(&output)?
    } else {
        let mut case = Case::create(&output, "Application memory validation")?;
        case.add_evidence(evidence.clone())?;
        case
    };
    // Read inventories through the case store, including archived engine outputs.
    for plugin in analysis::application::INVENTORY {
        if reuse {
            break;
        }
        if let Some(run) = document.runs.iter().rev().find(|r| {
            r.evidence_id == evidence.id
                && r.plugin == plugin
                && r.arguments.is_empty()
                && r.status == RunStatus::Completed
        }) {
            let table = ResultStore::at(&source).table(&run.id)?;
            let mut imported = run.clone();
            imported.status = RunStatus::Queued;
            case.queue(imported)?;
            let dir = case.run_dir(&run.id);
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(
                dir.join("stdout.json"),
                serde_json::to_vec(&table.rows.iter().map(|r| &r.fields).collect::<Vec<_>>())
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            case.finish(&run.id, &Outcome { status: RunStatus::Completed, exit_code: Some(0), message: "Imported source inventory for validation; evidence hash retained from source case".into(), table: Some(table) })?;
        }
    }
    let cancel = AtomicBool::new(false);
    let engine = Installation::discover(
        Settings {
            executable,
            offline: true,
            ..Default::default()
        },
        &cancel,
    )?;
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::APPLICATION.into());
    draft.arguments.insert(
        analysis::APPLICATION.into(),
        volgui::volatility::format_arguments(&arguments),
    );
    case.queue_batch(draft.prepare_in_case(&engine, &evidence, &case)?)?;
    while let Some(index) = case
        .document
        .runs
        .iter()
        .position(|r| r.status == RunStatus::Queued)
    {
        let run = case.document.runs[index].clone();
        if run.message == APPLICATION_RECOVERY_PENDING {
            let expanded = prepare_application_recovery(&case, &engine, &run)?;
            case.document.runs.splice(index..=index, expanded);
            case.save()?;
            continue;
        }
        case.document.runs[index].status = RunStatus::Running;
        case.document.runs[index].started_at = Some(now());
        case.save()?;
        eprintln!("{} {:?}", run.plugin, run.arguments);
        let outcome = if analysis::is_native(&run.plugin) {
            analysis::execute(&case.directory, &case.document, &run, &cancel, |s| {
                eprintln!("{s}")
            })
        } else {
            engine.execute(&run, &case.run_dir(&run.id), &cancel)
        };
        case.finish(&run.id, &outcome)?;
        if outcome.status != RunStatus::Completed {
            return Err(outcome.message);
        }
        if run.plugin == analysis::APPLICATION {
            let table = outcome.table.ok_or("Missing application findings")?;
            std::fs::write(
                case.directory.join("application.csv"),
                table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
            )
            .map_err(|e| e.to_string())?;
            println!("{}\nCase: {}", outcome.message, case.directory.display());
        }
    }
    Ok(())
}
