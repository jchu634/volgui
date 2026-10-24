//! Run one plugin on the first evidence in an existing case, without rehashing its acquisition.
use std::{path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    case::{Case, RunStatus, now},
    settings::Settings,
    volatility::Installation,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(args.next().ok_or(
        "Usage: run_plugin <case-directory> <vol-executable> <plugin> [plugin-arguments...]",
    )?);
    let executable = PathBuf::from(args.next().ok_or("Specify the external engine")?);
    let plugin = args
        .next()
        .ok_or("Specify a plugin")?
        .to_string_lossy()
        .into_owned();
    let arguments = args.map(|s| s.to_string_lossy().into_owned()).collect();
    let mut case = Case::open(&directory)?;
    let image = case
        .document
        .evidence
        .first()
        .ok_or("Case has no evidence")?
        .clone();
    let cancel = AtomicBool::new(false);
    let engine = Installation::discover(
        Settings {
            executable,
            offline: true,
            ..Default::default()
        },
        &cancel,
    )?;
    let run = engine.prepare(&image, &plugin, arguments, &case.directory.join("analyses"))?;
    case.queue(run.clone())?;
    let queued = case.document.runs.last_mut().unwrap();
    queued.status = RunStatus::Running;
    queued.started_at = Some(now());
    case.save()?;
    let outcome = engine.execute(&run, &case.run_dir(&run.id), &cancel);
    case.finish(&run.id, &outcome)?;
    println!(
        "{} · {} records\nOutput: {}",
        outcome.status.label(),
        outcome.table.as_ref().map_or(0, |t| t.rows.len()),
        case.run_dir(&run.id).display()
    );
    if outcome.status != RunStatus::Completed {
        return Err(outcome.message);
    }
    Ok(())
}
