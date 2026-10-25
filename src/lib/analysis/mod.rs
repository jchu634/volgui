//! Application analyses use the case queue and record store, just like engine jobs.
pub mod application;
mod browser;
mod process_memory;
pub use browser::memory::recovery_runs as browser_memory_runs;
pub mod network;
pub mod registry;
pub mod strings;

use crate::{
    case::{CaseSnapshot, Evidence, Run, RunStatus, now},
    volatility::{Outcome, Record, Table},
};
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub const BROWSER: &str = "volgui.browser.Activity";
pub const APPLICATION: &str = "volgui.application.Memory";
pub const STRINGS: &str = "volgui.strings.Search";
pub const NETWORK: &str = "volgui.network.Investigation";

pub fn is_native(plugin: &str) -> bool {
    matches!(plugin, BROWSER | APPLICATION | STRINGS | NETWORK)
}

pub fn prepare(evidence: &Evidence, plugin: &str, arguments: Vec<String>) -> Result<Run, String> {
    if !is_native(plugin) {
        return Err("Unknown application analysis".into());
    }
    evidence.check_metadata()?;
    if plugin == STRINGS {
        strings::validate(&arguments)?;
    }
    if plugin == APPLICATION {
        application::validate(&arguments)?;
    }
    if plugin == NETWORK && !arguments.is_empty() {
        return Err("Network investigation does not accept custom arguments".into());
    }
    Ok(Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: evidence.id.clone(),
        plugin: plugin.into(),
        arguments: arguments.clone(),
        command: std::iter::once("VolGUI".into())
            .chain(std::iter::once(plugin.into()))
            .chain(arguments)
            .collect(),
        engine_version: format!("VolGUI {}", env!("CARGO_PKG_VERSION")),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Queued,
        exit_code: None,
        row_count: 0,
        message: String::new(),
    })
}

pub fn execute(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: impl Fn(String),
) -> Outcome {
    let result = (|| {
        let evidence = document
            .evidence
            .iter()
            .find(|e| e.id == run.evidence_id)
            .ok_or("Evidence is no longer available")?;
        evidence.check_metadata()?;
        match run.plugin.as_str() {
            BROWSER => browser::analyze(directory, document, run, cancel, &progress),
            APPLICATION => application::analyze(directory, document, run, cancel, &progress),
            STRINGS => strings::search(&evidence.path, &run.arguments, cancel, &progress),
            NETWORK => network::analyze(directory, document, run, cancel, &progress),
            _ => Err("Unknown application analysis".into()),
        }
    })();
    let result = result.and_then(|(table, message)| {
        if cancel.load(Ordering::Relaxed) {
            return Err("Analysis cancelled".into());
        }
        let output = directory.join("analyses").join(&run.id);
        fs::create_dir_all(&output).map_err(|e| e.to_string())?;
        // Preserve the native analysis payload as a hashed provenance object.
        let rows: Vec<_> = table.rows.iter().map(|r| &r.fields).collect();
        let file = fs::File::create(output.join("stdout.json")).map_err(|e| e.to_string())?;
        serde_json::to_writer(file, &rows).map_err(|e| e.to_string())?;
        fs::write(output.join("stderr.log"), &message).map_err(|e| e.to_string())?;
        Ok((table, message))
    });
    match result {
        Ok((table, message)) => Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message,
            table: Some(table),
        },
        Err(message) => Outcome {
            status: if cancel.load(Ordering::Relaxed) {
                RunStatus::Cancelled
            } else {
                RunStatus::Failed
            },
            exit_code: None,
            message,
            table: None,
        },
    }
}

fn table(mut rows: Vec<Record>) -> Table {
    for row in &mut rows {
        crate::result_table::populate_domain(row);
    }
    let columns: BTreeSet<_> = rows.iter().flat_map(|r| r.fields.keys().cloned()).collect();
    Table {
        columns: columns.into_iter().collect(),
        rows,
    }
}

fn record(value: serde_json::Value) -> Record {
    Record {
        fields: value
            .as_object()
            .expect("analysis record object")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        depth: 0,
    }
}

/// Paths worth recovering from FileScan/Handles before parsing browser data.
pub fn browser_file(path: &str) -> bool {
    let path = path.replace('/', "\\").to_lowercase();
    let name = path.rsplit('\\').next().unwrap_or("");
    matches!(
        name,
        "history"
            | "places.sqlite"
            | "current session"
            | "last session"
            | "sessionstore.json"
            | "sessionstore.js"
            | "recovery.jsonlz4"
            | "previous.jsonlz4"
            | "sessionstore.jsonlz4"
            | "recovery.baklz4"
    ) || name.starts_with("session_") && path.contains("\\sessions\\")
}

pub fn browser_candidates(
    directory: &Path,
    document: &CaseSnapshot,
    evidence_id: &str,
    cancel: &AtomicBool,
) -> Result<Vec<crate::results::StoredRecord>, String> {
    let mut seen = BTreeSet::new();
    let runs: Vec<_> = document
        .runs
        .iter()
        .rev()
        .filter(|r| {
            r.evidence_id == evidence_id
                && r.status == RunStatus::Completed
                && matches!(
                    r.plugin.as_str(),
                    "windows.filescan.FileScan" | "windows.handles.Handles"
                )
        })
        .filter(|r| seen.insert(r.plugin.clone()))
        .map(|r| r.id.clone())
        .collect();
    if runs.is_empty() {
        return Ok(Vec::new());
    }
    let store = crate::results::ResultStore::at(directory);
    let index = store.query(&crate::results::Query {
        runs,
        ..Default::default()
    })?;
    let mut candidates = Vec::new();
    for ids in index.ids.chunks(256) {
        if cancel.load(Ordering::Relaxed) {
            return Err("Browser recovery cancelled".into());
        }
        for record in store.fetch(ids)? {
            if ["Name", "FileName", "Path"]
                .iter()
                .any(|name| browser_file(&record.record.text(name)))
            {
                candidates.push(record);
            }
        }
    }
    Ok(candidates)
}

pub fn browser_recovery_runs(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &Evidence,
    engine: &crate::volatility::Installation,
    physical: bool,
    cancel: &AtomicBool,
) -> Result<Vec<Run>, String> {
    let mut runs = Vec::new();
    let mut seen = BTreeSet::new();
    for record in browser_candidates(directory, document, &evidence.id, cancel)? {
        let source = document
            .runs
            .iter()
            .find(|r| r.id == record.run_id)
            .ok_or("Missing source analysis")?;
        let Some(target) =
            crate::extracted_files::FileDumpTarget::from_record(&source.plugin, &record.record)
        else {
            continue;
        };
        let arguments = target.arguments(physical);
        if !seen.insert(arguments.clone())
            || document.runs.iter().any(|r| {
                r.plugin == crate::extracted_files::DUMP_FILES
                    && r.evidence_id == evidence.id
                    && r.arguments == arguments
                    && matches!(
                        r.status,
                        RunStatus::Completed | RunStatus::Running | RunStatus::Queued
                    )
            })
        {
            continue;
        }
        if runs.len() >= 512 {
            return Err("More than 512 browser file objects found. Extract the desired profile files in Files, then choose Analyze recovered files.".into());
        }
        runs.push(engine.prepare(
            evidence,
            crate::extracted_files::DUMP_FILES,
            arguments,
            &directory.join("analyses"),
        )?);
    }
    runs.push(prepare(evidence, BROWSER, vec![])?);
    Ok(runs)
}
