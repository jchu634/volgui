//! Exercise the same network chooser queue as the desktop against a capture.
use std::{path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analyses::AnalysisDraft,
    analysis,
    artifacts::OperatingSystem,
    case::{Case, Evidence, RunStatus, now},
    settings::Settings,
    volatility::Installation,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let capture = PathBuf::from(
        args.next()
            .ok_or("Usage: validate_network <capture> <new-case> <engine>")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify a new case directory")?);
    let executable = PathBuf::from(args.next().ok_or("Specify an engine executable")?);
    let cancel = AtomicBool::new(false);
    let mut evidence = Evidence::inspect(&capture, &cancel, |_, _| {})?;
    evidence.operating_system = OperatingSystem::Windows;
    let mut case = Case::create(&output, "Network investigation validation")?;
    case.add_evidence(evidence.clone())?;
    let engine = Installation::discover(
        Settings {
            executable,
            ..Settings::default()
        },
        &cancel,
    )?;
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::NETWORK.into());
    case.queue_batch(draft.prepare_in_case(&engine, &evidence, &case)?)?;
    while let Some(index) = case
        .document
        .runs
        .iter()
        .position(|r| r.status == RunStatus::Queued)
    {
        case.document.runs[index].status = RunStatus::Running;
        case.document.runs[index].started_at = Some(now());
        case.save()?;
        let run = case.document.runs[index].clone();
        eprintln!("Running {}", run.plugin);
        let outcome = if analysis::is_native(&run.plugin) {
            analysis::execute(&case.directory, &case.document, &run, &cancel, |message| {
                eprintln!("{message}");
            })
        } else {
            engine.execute(&run, &case.run_dir(&run.id), &cancel)
        };
        case.finish(&run.id, &outcome)?;
        eprintln!(
            "{}: {} rows, {}",
            run.plugin,
            case.document.runs[index].row_count,
            outcome.status.label()
        );
        if run.plugin == analysis::NETWORK {
            if outcome.status != RunStatus::Completed {
                return Err(outcome.message);
            }
            let table = case.results(&run.id)?;
            std::fs::write(
                case.directory.join("network.csv"),
                table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
            )
            .map_err(|e| e.to_string())?;
            println!("{}\nCase: {}", outcome.message, case.directory.display());
        }
    }
    Ok(())
}
