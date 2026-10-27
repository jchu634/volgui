//! Application analyses use the case queue and record store, just like engine jobs.
pub mod application;
mod browser;
pub mod downloads;
pub mod files;
mod partial;
mod process_memory;
pub use browser::memory::recovery_runs as browser_memory_runs;
pub mod network;
pub mod network_attribution;
pub mod quarantine;
pub mod registry;
pub mod strings;

use crate::{
    case::{CaseSnapshot, Evidence, Run, RunStatus, now},
    volatility::{Outcome, Record, Table},
};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufWriter, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub const BROWSER: &str = "volgui.browser.Activity";
pub const APPLICATION: &str = "volgui.application.Memory";
pub const STRINGS: &str = "volgui.strings.Search";
pub const NETWORK: &str = "volgui.network.Investigation";
pub const NETWORK_ATTRIBUTION: &str = "volgui.network.ProcessAttribution";
pub const FILES: &str = "volgui.files.Recovery";
pub const FILE_PATHS: &str = "volgui.files.PathReferences";
pub const DOWNLOADS: &str = "volgui.downloads.Investigation";
pub const QUARANTINE: &str = "volgui.quarantine.Investigation";

/// Inventories must be unfiltered and belong to the report's evidence.
/// Queue planning can accept active inputs; execution requires saved results.
pub fn missing_source_inventories<'a>(
    runs: impl IntoIterator<Item = &'a Run>,
    evidence_id: &str,
    sources: &[&'static str],
    allow_active: bool,
) -> Vec<&'static str> {
    let available: BTreeSet<_> = runs
        .into_iter()
        .filter(|run| {
            run.evidence_id == evidence_id
                && run.arguments.is_empty()
                && (run.status.has_results()
                    || allow_active && matches!(run.status, RunStatus::Queued | RunStatus::Running))
        })
        .map(|run| run.plugin.as_str())
        .collect();
    sources
        .iter()
        .copied()
        .filter(|id| !available.contains(id))
        .collect()
}

pub(crate) fn require_source_inventories(
    document: &CaseSnapshot,
    evidence_id: &str,
    sources: &[&'static str],
) -> Result<(), String> {
    let missing = missing_source_inventories(&document.runs, evidence_id, sources, false);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Missing source inventories: {}. Complete these unfiltered prerequisites for this evidence before running the investigation.",
            missing.join(", ")
        ))
    }
}

pub fn is_native(plugin: &str) -> bool {
    matches!(
        plugin,
        BROWSER
            | APPLICATION
            | STRINGS
            | NETWORK
            | NETWORK_ATTRIBUTION
            | FILES
            | FILE_PATHS
            | DOWNLOADS
            | QUARANTINE
    )
}

pub fn prepare(evidence: &Evidence, plugin: &str, arguments: Vec<String>) -> Result<Run, String> {
    if !is_native(plugin) {
        return Err("Unknown application analysis".into());
    }
    if plugin != QUARANTINE || !quarantine::passive_arguments(&arguments) {
        evidence.check_metadata()?;
    }
    if plugin == STRINGS {
        strings::validate(&arguments)?;
    }
    if plugin == APPLICATION {
        application::validate(&arguments)?;
    }
    if plugin == NETWORK_ATTRIBUTION {
        network_attribution::validate(&arguments)?;
    }
    if plugin == FILES {
        files::physical_offset(&arguments)?;
    }
    if plugin == FILE_PATHS && !arguments.is_empty() {
        return Err("Executable path discovery does not accept custom arguments".into());
    }
    if plugin == NETWORK && !arguments.is_empty() {
        return Err("Network investigation does not accept custom arguments".into());
    }
    if plugin == DOWNLOADS && !arguments.is_empty() {
        return Err("Download investigation does not accept custom arguments".into());
    }
    if plugin == QUARANTINE && !arguments.is_empty() && !quarantine::passive_arguments(&arguments) {
        return Err("Quarantine investigation does not accept custom arguments".into());
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

/// Native parsing, shared by the queue and the stage profiler.
pub fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: impl Fn(String),
) -> Result<(Table, String), String> {
    let evidence = document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    if !quarantine::is_passive(run) {
        evidence.check_metadata()?;
    }
    match run.plugin.as_str() {
        BROWSER => browser::analyze(directory, document, run, cancel, &progress),
        APPLICATION => application::analyze(directory, document, run, cancel, &progress),
        STRINGS => strings::search(&evidence.path, &run.arguments, cancel, &progress),
        NETWORK => network::analyze(directory, document, run, cancel, &progress),
        NETWORK_ATTRIBUTION => {
            network_attribution::analyze(directory, document, run, cancel, &progress)
        }
        FILES => files::analyze(directory, document, run, cancel, &progress),
        FILE_PATHS => files::path_references(&evidence.path, cancel, &progress),
        DOWNLOADS => downloads::analyze(directory, document, run, cancel, &progress),
        QUARANTINE => quarantine::analyze(directory, document, run, cancel, &progress),
        _ => Err("Unknown application analysis".into()),
    }
}

/// Persist native findings before their object-store capture.
pub fn save_results(
    directory: &Path,
    run: &Run,
    table: &Table,
    message: &str,
) -> Result<(), String> {
    let output = directory.join("analyses").join(&run.id);
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let rows: Vec<_> = table.rows.iter().map(|r| &r.fields).collect();
    let file = fs::File::create(output.join("stdout.json")).map_err(|e| e.to_string())?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file);
    serde_json::to_writer(&mut writer, &rows).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    fs::write(output.join("stderr.log"), message).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn execute(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: impl Fn(String),
) -> Outcome {
    let result = analyze(directory, document, run, cancel, progress);
    let result = result.and_then(|(table, mut message)| {
        if cancel.load(Ordering::Relaxed) {
            return Err("Analysis cancelled".into());
        }
        if let Some(first) = table.warnings.first() {
            let remaining = table.warnings.len() - 1;
            let more = if remaining > 0 {
                format!(" {remaining} additional coverage warnings are listed below.")
            } else {
                String::new()
            };
            message = format!("Incomplete coverage. {first}{more}\n\n{message}");
        }
        for warning in &table.warnings {
            if !message.contains(warning) {
                message.push_str(&format!("\n{warning}"));
            }
        }
        save_results(directory, run, &table, &message)?;
        Ok((table, message))
    });
    match result {
        Ok((table, message)) => Outcome {
            status: if table.warnings.is_empty() {
                RunStatus::Completed
            } else {
                RunStatus::Warning
            },
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
        warnings: Vec::new(),
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
                && r.status.has_results()
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
                        RunStatus::Completed
                            | RunStatus::Warning
                            | RunStatus::Running
                            | RunStatus::Queued
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
