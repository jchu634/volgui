//! Replay current Network candidate discovery without changing the source case.
use std::{collections::BTreeSet, fs, path::PathBuf, sync::atomic::AtomicBool, time::Instant};
use volgui::{
    analysis::{
        application::{MEMMAP, VADINFO},
        network_attribution::{self, DISCOVERY},
    },
    case::CaseSnapshot,
    settings::Settings,
    volatility::{Installation, Plugin},
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source = PathBuf::from(
        args.next()
            .ok_or("Usage: profile_network_discovery <source-case> <output-json>")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify output JSON")?);
    let doc = CaseSnapshot::load(&source)?;
    let evidence = doc.evidence.first().ok_or("Missing evidence")?;
    let previous = doc
        .runs
        .iter()
        .rev()
        .find(|r| r.plugin == DISCOVERY && r.evidence_id == evidence.id)
        .ok_or("A previous discovery command is needed for a comparable replay")?;
    let engine = Installation {
        settings: Settings::load()?,
        version: previous.engine_version.clone(),
        user_memory_dumps: true,
        plugins: [MEMMAP, VADINFO, DISCOVERY]
            .map(|id| Plugin {
                id: id.into(),
                description: String::new(),
            })
            .into(),
    };
    let cancel = AtomicBool::new(false);
    let prepared =
        network_attribution::recovery_runs(&source, &doc, evidence, &engine, &[], &cancel)?;
    let discovery = prepared
        .iter()
        .find(|r| r.plugin == DISCOVERY)
        .ok_or("Current discovery already exists in this case")?;
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut run = previous.clone();
    let index = run
        .command
        .iter()
        .position(|arg| arg == DISCOVERY)
        .ok_or("Missing discovery plugin in saved command")?;
    run.command.truncate(index + 1);
    run.command.extend(discovery.arguments.clone());
    let index = run
        .command
        .iter()
        .position(|arg| arg == "-o")
        .ok_or("Missing output option")?;
    run.command[index + 1] = scratch.path().display().to_string();
    let started = Instant::now();
    let outcome = engine.execute(&run, scratch.path(), &cancel);
    let seconds = started.elapsed().as_secs_f64();
    if !outcome.status.has_results() {
        return Err(outcome.message);
    }
    let table = outcome.table.ok_or("Discovery returned no table")?;
    let pids = table
        .rows
        .iter()
        .filter_map(|r| r.fields.get("PID")?.as_u64())
        .collect::<BTreeSet<_>>();
    let observations = table.rows.iter().map(|r| &r.fields).collect::<Vec<_>>();
    fs::write(
        output.with_extension("observations.json"),
        serde_json::to_vec_pretty(&observations).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let report = serde_json::json!({"seconds":seconds,"observations":table.rows.len(),"candidate_pids":pids,"arguments":discovery.arguments,"run":discovery});
    fs::write(
        &output,
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "{seconds:.3}s, {} observations, {} candidate PIDs",
        table.rows.len(),
        pids.len()
    );
    Ok(())
}
