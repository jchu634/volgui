//! Time result loading, output archiving and SQLite import in an isolated case.
use sha2::{Digest, Sha256};
use std::{fs, io, path::PathBuf, sync::atomic::AtomicBool, time::Instant};
use volgui::{
    case::{Case, CaseSnapshot, RunStatus},
    object_store::{self, ObjectStore},
    results::ResultStore,
    volatility::Table,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source =
        PathBuf::from(args.next().ok_or(
            "Usage: benchmark_import <source-case> <run-id> <capture-directory> [repeats]",
        )?);
    let id = args.next().ok_or("Specify a source run ID")?;
    let capture = PathBuf::from(args.next().ok_or("Specify a raw capture directory")?);
    let repeats: usize = args
        .next()
        .map(|value| value.to_string_lossy().parse())
        .transpose()
        .map_err(|_| "Repeats must be a positive integer")?
        .unwrap_or(1);
    if repeats == 0 || args.next().is_some() {
        return Err("Specify a positive repeat count and no extra arguments".into());
    }
    let document = CaseSnapshot::load(&source)?;
    let mut run = document
        .runs
        .iter()
        .find(|run| run.id == id.to_string_lossy())
        .ok_or("Source run not found")?
        .clone();
    let evidence = document
        .evidence
        .iter()
        .find(|evidence| evidence.id == run.evidence_id)
        .ok_or("Source evidence not found")?
        .clone();
    // Keep benchmark I/O on the capture's volume and the source case untouched.
    let temp = tempfile::tempdir_in(capture.parent().ok_or("Capture needs a parent")?)
        .map_err(|e| e.to_string())?;
    let mut case = Case::create(&temp.path().join("case"), "Import benchmark")?;
    case.add_evidence(evidence)?;
    run.status = RunStatus::Queued;
    run.started_at = None;
    run.finished_at = None;
    run.exit_code = None;
    run.row_count = 0;
    run.message.clear();
    let mut files = Vec::new();
    for entry in fs::read_dir(&capture).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            return Err("Use a capture containing only regular output files".into());
        }
        files.push(entry.path());
    }
    let cancel = AtomicBool::new(false);
    for iteration in 1..=repeats {
        run.id = uuid::Uuid::new_v4().to_string();
        case.queue(run.clone())?;
        let directory = case.run_dir(&run.id);
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let mut bytes = 0;
        for path in &files {
            bytes += fs::copy(
                path,
                directory.join(path.file_name().ok_or("Missing filename")?),
            )
            .map_err(|e| e.to_string())?;
        }
        let started = Instant::now();
        let table = Table::read(&directory.join("stdout.json"))?;
        let parse = started.elapsed();
        eprintln!(
            "JSON: {:.3}s, {} rows",
            parse.as_secs_f64(),
            table.rows.len()
        );
        let started = Instant::now();
        ObjectStore::at(&case.directory).capture_run(&run.id, &cancel)?;
        let archive = started.elapsed();
        eprintln!("Archive: {:.3}s, {bytes} bytes", archive.as_secs_f64());
        let started = Instant::now();
        ResultStore::at(&case.directory).insert_cancellable(&run, &table, &cancel)?;
        let import = started.elapsed();
        let stored = ResultStore::at(&case.directory).table(&run.id)?;
        if stored.columns != table.columns
            || stored.rows.len() != table.rows.len()
            || stored
                .rows
                .iter()
                .zip(&table.rows)
                .any(|(stored, original)| {
                    stored.depth != original.depth || stored.fields != original.fields
                })
        {
            return Err("Stored observations differ from the input table".into());
        }
        drop(stored);
        // Outside the measured stages, authenticate every archived byte and compare
        // the complete file digest against the untouched raw capture.
        for path in &files {
            let archived = directory.join(path.file_name().ok_or("Missing filename")?);
            let mut digest = Sha256::new();
            let mut source = fs::File::open(path).map_err(|e| e.to_string())?;
            io::copy(&mut source, &mut digest).map_err(|e| e.to_string())?;
            let expected = format!("{:x}", digest.finalize());
            if object_store::stored_hash(&archived)?.as_deref() != Some(expected.as_str()) {
                return Err("Archived SHA-256 differs from the raw capture".into());
            }
            let mut reader = object_store::open(&archived)?;
            let verified = io::copy(&mut reader, &mut io::sink()).map_err(|e| e.to_string())?;
            if verified != fs::metadata(path).map_err(|e| e.to_string())?.len() {
                return Err("Archived length differs from the raw capture".into());
            }
        }
        println!(
            "{}",
            serde_json::json!({
                "iteration": iteration,
                "parse_seconds": parse.as_secs_f64(),
                "archive_seconds": archive.as_secs_f64(),
                "import_seconds": import.as_secs_f64(),
                "rows": table.rows.len(), "output_bytes": bytes,
                "verified": true,
            })
        );
    }
    Ok(())
}
