//! Attribute a selected process using saved collections, leaving the source case unchanged.
use std::{path::PathBuf, sync::atomic::AtomicBool};
use volgui::{analysis, case::CaseSnapshot, settings::Settings, volatility::Installation};
fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source =
        PathBuf::from(args.next().ok_or(
            "Usage: reparse_attribution <source-case> <output-directory> <engine> --pid PID",
        )?);
    let output = PathBuf::from(args.next().ok_or("Specify output directory")?);
    let engine = PathBuf::from(args.next().ok_or("Specify engine")?);
    let arguments = args
        .map(|s| s.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let cancel = AtomicBool::new(false);
    let engine = Installation::discover(
        Settings {
            executable: engine,
            ..Settings::default()
        },
        &cancel,
    )?;
    let mut document = CaseSnapshot::load(&source)?;
    let evidence = document.evidence.first().ok_or("Missing evidence")?.clone();
    let mut runs = analysis::network_attribution::recovery_runs(
        &source, &document, &evidence, &engine, &arguments, &cancel,
    )?;
    if runs.len() != 1 || runs[0].message == analysis::network_attribution::PENDING {
        return Err("This read-only example requires already collected Memmap and VadInfo sources; collect them in a separate validation case first".into());
    }
    let run = runs.remove(0);
    document.runs.push(run.clone());
    let started = std::time::Instant::now();
    let (table, message) =
        analysis::network_attribution::analyze(&source, &document, &run, &cancel, &|s| {
            eprintln!("{s}")
        })?;
    std::fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let values: Vec<_> = table.rows.iter().map(|r| &r.fields).collect();
    std::fs::write(
        output.join("findings.json"),
        serde_json::to_vec_pretty(&values).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        output.join("run.json"),
        serde_json::to_vec_pretty(&run).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "{message}\nParse seconds: {:.6}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
