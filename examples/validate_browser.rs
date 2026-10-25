//! Validate browser recovery in a separate case, reusing the source evidence fingerprint.
use std::{collections::BTreeSet, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analysis,
    case::{Case, CaseDocument, RunStatus, now},
    settings::Settings,
    volatility::{Installation, Table},
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source = PathBuf::from(
        args.next()
            .ok_or("Usage: validate_browser <source-case> <new-case> <vol-executable> [PID ...]")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify a new case directory")?);
    let executable = PathBuf::from(args.next().ok_or("Specify the external engine")?);
    let selected: BTreeSet<_> = args.map(|a| a.to_string_lossy().into_owned()).collect();
    let document: CaseDocument = serde_json::from_reader(
        std::fs::File::open(source.join("case.volgui.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let cancel = AtomicBool::new(false);
    let evidence = document
        .evidence
        .first()
        .ok_or("Source case has no evidence")?
        .clone();
    evidence.check_metadata()?;
    let mut case = Case::create(&output, "Browser memory validation")?;
    case.add_evidence(evidence.clone())?;
    for plugin in ["windows.pslist.PsList", "windows.cmdline.CmdLine"] {
        if let Some(run) = document.runs.iter().rev().find(|r| {
            r.plugin == plugin && r.evidence_id == evidence.id && r.status == RunStatus::Completed
        }) {
            let table = Table::read(&source.join("analyses").join(&run.id).join("stdout.json"))?;
            let mut imported = run.clone();
            imported.status = RunStatus::Queued;
            case.queue(imported)?;
            let directory = case.run_dir(&run.id);
            std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
            std::fs::copy(
                source.join("analyses").join(&run.id).join("stdout.json"),
                directory.join("stdout.json"),
            )
            .map_err(|e| e.to_string())?;
            case.finish(
                &run.id,
                &volgui::volatility::Outcome {
                    status: RunStatus::Completed,
                    exit_code: Some(0),
                    message: "Imported source inventory for validation".into(),
                    table: Some(table),
                },
            )?;
        }
    }
    let engine = Installation::discover(
        Settings {
            executable,
            offline: true,
            ..Default::default()
        },
        &cancel,
    )?;
    let runs = analysis::browser_memory_runs(
        &case.directory,
        &case.document,
        &evidence,
        &engine,
        &cancel,
    )?;
    let runs: Vec<_> = runs
        .into_iter()
        .filter(|r| {
            r.plugin == analysis::BROWSER
                || selected.is_empty()
                || r.arguments.get(1).is_some_and(|pid| selected.contains(pid))
        })
        .collect();
    for run in runs {
        case.queue(run.clone())?;
        let queued = case.document.runs.last_mut().unwrap();
        queued.status = RunStatus::Running;
        queued.started_at = Some(now());
        case.save()?;
        eprintln!("{} {:?}", run.plugin, run.arguments);
        let outcome = if analysis::is_native(&run.plugin) {
            analysis::execute(&case.directory, &case.document, &run, &cancel, |message| {
                eprintln!("{message}")
            })
        } else {
            engine.execute(&run, &case.run_dir(&run.id), &cancel)
        };
        case.finish(&run.id, &outcome)?;
        if outcome.status != RunStatus::Completed {
            return Err(outcome.message);
        }
        if run.plugin == analysis::BROWSER {
            let table = outcome.table.unwrap();
            for row in table
                .rows
                .iter()
                .filter(|row| row.text("Kind") == "Memory search")
            {
                println!(
                    "{} PID {}: {}",
                    row.text("Browser"),
                    row.text("PID"),
                    row.text("Search terms")
                );
            }
            std::fs::write(
                case.directory.join("browser.csv"),
                table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
            )
            .map_err(|e| e.to_string())?;
            println!("{}\nCase: {}", outcome.message, case.directory.display());
        }
    }
    Ok(())
}
