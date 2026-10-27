//! Exercise the desktop attribution queue in a new case, reusing compatible saved inputs.
use std::{fs, io, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analyses::{AnalysisDraft, prepare_network_attribution},
    analysis,
    case::{Case, CaseSnapshot, RunStatus},
    results::ResultStore,
    settings::Settings,
    volatility::{Installation, Outcome},
};
fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source = PathBuf::from(
        args.next()
            .ok_or("Usage: validate_attribution <source-case> <new-case> <engine> [--pid PID]")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify a new case directory")?);
    let executable = PathBuf::from(args.next().ok_or("Specify engine")?);
    let args = args
        .map(|s| s.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    analysis::network_attribution::validate(&args)?;
    let pid = args
        .windows(2)
        .find(|p| p[0] == "--pid")
        .and_then(|p| p[1].parse::<u64>().ok());
    let doc = CaseSnapshot::load(&source)?;
    let evidence = doc.evidence.first().ok_or("Missing evidence")?.clone();
    let mut case = Case::create(&output, "Network attribution validation")?;
    case.add_evidence(evidence.clone())?;
    let mut imports = Vec::new();
    for plugin in analysis::application::INVENTORY {
        if let Some(run) = doc.runs.iter().rev().find(|r| {
            r.evidence_id == evidence.id
                && r.plugin == plugin
                && r.arguments.is_empty()
                && r.status == RunStatus::Completed
        }) {
            imports.push(run);
        }
    }
    if let Some(pid) = pid {
        for plugin in [
            analysis::application::VADINFO,
            analysis::application::MEMMAP,
        ] {
            if let Some(run) = doc.runs.iter().rev().find(|r| {
                r.evidence_id == evidence.id
                    && r.plugin == plugin
                    && r.status == RunStatus::Completed
                    && r.arguments
                        .windows(2)
                        .any(|p| p[0] == "--pid" && p[1] == pid.to_string())
            }) {
                imports.push(run);
            }
        }
    }
    for run in imports {
        let table = ResultStore::at(&source).table(&run.id)?;
        let mut imported = run.clone();
        imported.status = RunStatus::Queued;
        case.queue(imported)?;
        if run.plugin == analysis::application::MEMMAP {
            let filename = format!("pid.{}.dmp", pid.ok_or("Dump has no selected PID")?);
            let path = case.run_dir(&run.id);
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            let mut input = volgui::extracted_files::open_artifact(
                &source.join("analyses").join(&run.id).join(&filename),
            )?;
            let mut file = fs::File::create(path.join(filename)).map_err(|e| e.to_string())?;
            io::copy(&mut input, &mut file).map_err(|e| e.to_string())?;
        }
        case.finish(
            &run.id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                message: "Imported validation input; original evidence and run identity retained"
                    .into(),
                table: Some(table),
            },
        )?;
    }
    let cancel = AtomicBool::new(false);
    let engine = Installation::discover(
        Settings {
            executable,
            ..Settings::load().unwrap_or_default()
        },
        &cancel,
    )?;
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::NETWORK_ATTRIBUTION.into());
    draft.arguments.insert(
        analysis::NETWORK_ATTRIBUTION.into(),
        volgui::volatility::format_arguments(&args),
    );
    case.queue_batch(draft.prepare_in_case(&engine, &evidence, &case)?)?;
    while let Some(index) = case
        .document
        .runs
        .iter()
        .position(|r| r.status == RunStatus::Queued)
    {
        let run = case.document.runs[index].clone();
        if run.plugin == analysis::NETWORK_ATTRIBUTION
            && run.message == analysis::network_attribution::PENDING
        {
            let runs = prepare_network_attribution(&case, &engine, &run)?;
            case.document.runs.splice(index..=index, runs);
            case.save()?;
            continue;
        }
        eprintln!("Running {} {:?}", run.plugin, run.arguments);
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
        if run.plugin == analysis::NETWORK_ATTRIBUTION {
            let table = outcome.table.ok_or("No attribution result")?;
            let rows: Vec<_> = table.rows.iter().map(|r| &r.fields).collect();
            fs::write(
                output.join("findings.json"),
                serde_json::to_vec_pretty(&rows).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            println!("{}\nCase: {}", outcome.message, output.display());
        }
    }
    Ok(())
}
