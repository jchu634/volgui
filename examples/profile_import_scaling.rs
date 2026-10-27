//! Compare imports in a fresh case and an isolated copy of a populated catalog.
//! No binary outputs are opened or published. The source is opened read-only.
use std::{fs, path::PathBuf, sync::atomic::AtomicBool, time::Instant};
use volgui::{
    case::{Case, CaseSnapshot, RunStatus},
    results::ResultStore,
    volatility::Table,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source =
        PathBuf::from(args.next().ok_or(
            "Usage: profile_import_scaling <source-case> <output-json> <run-id> [run-id...]",
        )?);
    let output = PathBuf::from(args.next().ok_or("Specify output JSON")?);
    let ids: Vec<_> = args.map(|s| s.to_string_lossy().into_owned()).collect();
    if ids.is_empty() {
        return Err("Specify at least one source run".into());
    }
    let parent = source.parent().ok_or("Source needs a parent directory")?;
    let temp = tempfile::tempdir_in(parent).map_err(|e| e.to_string())?;
    let populated = temp.path().join("populated");
    fs::create_dir(&populated).map_err(|e| e.to_string())?;
    let db = rusqlite::Connection::open_with_flags(
        source.join("case.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| e.to_string())?;
    db.execute_batch("BEGIN; SELECT id FROM case_meta;")
        .map_err(|e| e.to_string())?;
    eprintln!("Backing up populated input catalog");
    db.backup("main", populated.join("case.sqlite"), None)
        .map_err(|e| e.to_string())?;
    db.execute_batch("ROLLBACK;").map_err(|e| e.to_string())?;
    drop(db);
    let db = rusqlite::Connection::open_with_flags(
        populated.join("case.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| e.to_string())?;
    let observations: i64 = db
        .query_row("SELECT count(*) FROM observations", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let process_observations: i64 = db
        .query_row(
            "SELECT count(*) FROM observations WHERE process_role!='none'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    drop(db);
    let document = CaseSnapshot::load(&populated)?;
    let mut populated = Case::open(&populated)?;
    let cancel = AtomicBool::new(false);
    let mut measurements = Vec::new();
    let mut inputs = Vec::new();
    for id in ids {
        let run = document
            .runs
            .iter()
            .find(|r| r.id == id)
            .ok_or("Unknown run ID")?;
        let table = ResultStore::at(&populated.directory).table(&id)?;
        inputs.push((run.clone(), table));
    }
    // An empty import still executes the production reconciliation path.
    // It isolates catalog-wide work from row parsing and row insertion.
    inputs.insert(
        0,
        (
            inputs[0].0.clone(),
            Table {
                warnings: Vec::new(),
                columns: vec![],
                rows: vec![],
            },
        ),
    );
    for (template, table) in inputs {
        let evidence = document
            .evidence
            .iter()
            .find(|e| e.id == template.evidence_id)
            .ok_or("Missing source evidence")?;
        for iteration in 1..=3 {
            for mode in ["fresh", "populated"] {
                let mut fresh = if mode == "fresh" {
                    let mut case = Case::create(
                        &temp.path().join(uuid::Uuid::new_v4().to_string()),
                        "Import profile",
                    )?;
                    case.add_evidence(evidence.clone())?;
                    Some(case)
                } else {
                    None
                };
                let case = fresh.as_mut().unwrap_or(&mut populated);
                let mut run = template.clone();
                run.id = uuid::Uuid::new_v4().to_string();
                run.status = RunStatus::Queued;
                run.started_at = None;
                run.finished_at = None;
                run.exit_code = None;
                run.row_count = 0;
                run.message.clear();
                case.queue(run.clone())?;
                let store = ResultStore::at(&case.directory);
                let started = Instant::now();
                store.insert_cancellable(&run, &table, &cancel)?;
                let seconds = started.elapsed().as_secs_f64();
                let stored = store.table(&run.id)?;
                if stored.columns != table.columns
                    || stored.rows.len() != table.rows.len()
                    || stored
                        .rows
                        .iter()
                        .zip(&table.rows)
                        .any(|(a, b)| a.fields != b.fields || a.depth != b.depth)
                {
                    return Err("Imported rows changed".into());
                }
                eprintln!(
                    "{mode}, {}, {} rows: {seconds:.3}s",
                    template.plugin,
                    table.rows.len()
                );
                measurements.push(serde_json::json!({
                    "mode": mode, "plugin": template.plugin, "source_run": template.id,
                    "iteration": iteration, "rows": table.rows.len(), "seconds": seconds,
                    "verified": true, "populated_observations": observations,
                    "populated_process_observations": process_observations,
                }));
                if let Some(parent) = output.parent() {
                    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                fs::write(
                    &output,
                    serde_json::to_vec_pretty(&measurements).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}
