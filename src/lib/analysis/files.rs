//! File recovery outcomes, shared by preprocessing and the file browsers.
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    case::{CaseSnapshot, Evidence, Run, RunStatus},
    extracted_files::{self, DUMP_FILES, FileDumpTarget},
    result_tree::TreeEntry,
    results::{ResultStore, StoredRecord},
    volatility::{Installation, Record, Table},
};

mod paths;

pub const SOURCES: [&str; 2] = ["windows.filescan.FileScan", "windows.handles.Handles"];
pub const PENDING: &str = "Waiting to prepare file and document recovery";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryState {
    Untested,
    Recovered,
    Uncached,
    Failed,
    Unsupported,
    Pending,
    Unavailable,
    Referenced,
}

impl RecoveryState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Untested => "Not tested",
            Self::Recovered => "Recovered",
            Self::Uncached => "No cached contents",
            Self::Failed => "Extraction failed",
            Self::Unsupported => "Cannot dump this object",
            Self::Pending => "Recovery queued",
            Self::Unavailable => "Recovered output unavailable",
            Self::Referenced => "Path reference only",
        }
    }

    pub fn unavailable(self) -> bool {
        matches!(
            self,
            Self::Uncached | Self::Failed | Self::Unsupported | Self::Unavailable
        )
    }
}

/// Directory index streams describe directory entries, not document contents.
/// Do not discard other NTFS metadata such as $Mft or arbitrary dollar-prefixed files.
pub fn pseudo_file(path: &str) -> bool {
    let path = path.trim_end_matches(['/', '\\']).to_ascii_lowercase();
    let name = path.rsplit(['/', '\\']).next().unwrap_or("");
    name == "$directory"
        || name.starts_with("$directory:")
        || name.ends_with(":$i30:$index_allocation")
        || name.ends_with(":$i30:$index_root")
}

pub fn file_path(record: &Record) -> String {
    ["Name", "FileName", "Path", "FilePath", "FullPath"]
        .iter()
        .map(|field| record.text(field))
        .find(|path| !path.is_empty())
        .unwrap_or_default()
}

pub fn physical_offset(arguments: &[String]) -> Result<bool, String> {
    match arguments {
        [] => Ok(false),
        [flag] if flag == "--physical" => Ok(true),
        _ => {
            Err("File recovery accepts only --physical for older FileScan physical offsets".into())
        }
    }
}

pub struct Recovery {
    pub state: RecoveryState,
    pub run_id: String,
}

pub struct RecoveryIndex {
    objects: HashMap<(String, Vec<String>), Recovery>,
    plugins: HashMap<String, (String, String)>,
    dump_states: HashMap<String, RecoveryState>,
    output_states: HashMap<(String, String), RecoveryState>,
}

impl RecoveryIndex {
    pub fn load(directory: &Path, document: &CaseSnapshot) -> Result<Self, String> {
        // One metadata query for all dumps; opening a connection per file makes large
        // scans unnecessarily expensive. Missing capture metadata falls back to disk.
        let db = crate::database::connect(directory)?;
        let mut statement = db.prepare(
            "SELECT run_id,MAX(CASE WHEN name NOT IN ('stdout.json','stderr.log') AND sha256 IS NOT NULL AND blocked_reason IS NULL AND size>0 THEN 1 ELSE 0 END),SUM(CASE WHEN name NOT IN ('stdout.json','stderr.log') THEN 1 ELSE 0 END) FROM analysis_outputs GROUP BY run_id",
        ).map_err(|e| e.to_string())?;
        let outputs = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    (r.get::<_, bool>(1)?, r.get::<_, i64>(2)?),
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(|e| e.to_string())?;
        let mut statement = db.prepare(
            "SELECT run_id,name,sha256 IS NOT NULL AND blocked_reason IS NULL AND size>0 FROM analysis_outputs WHERE name NOT IN ('stdout.json','stderr.log')",
        ).map_err(|e| e.to_string())?;
        let output_states = statement
            .query_map([], |r| {
                Ok((
                    (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
                    if r.get::<_, bool>(2)? {
                        RecoveryState::Recovered
                    } else {
                        RecoveryState::Unavailable
                    },
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(|e| e.to_string())?;
        let mut objects: HashMap<_, Recovery> = HashMap::new();
        let mut dump_states = HashMap::new();
        for run in document.runs.iter().filter(|r| r.plugin == DUMP_FILES) {
            let state = match run.status {
                RunStatus::Completed | RunStatus::Warning => match outputs.get(&run.id) {
                    Some((true, _)) => RecoveryState::Recovered,
                    Some((false, 0)) => RecoveryState::Uncached,
                    Some((false, _)) => RecoveryState::Unavailable,
                    None => {
                        let output = directory.join("analyses").join(&run.id);
                        match extracted_files::listing(&output) {
                            Ok(files)
                                if files.iter().any(|f| {
                                    f.available
                                        && extracted_files::open_artifact(&f.path).is_ok_and(
                                            |reader| reader.metadata().is_ok_and(|m| !m.is_empty()),
                                        )
                                }) =>
                            {
                                RecoveryState::Recovered
                            }
                            Ok(files) if files.is_empty() => RecoveryState::Uncached,
                            Ok(_) | Err(_) => RecoveryState::Unavailable,
                        }
                    }
                },
                RunStatus::Failed => RecoveryState::Failed,
                RunStatus::Queued | RunStatus::Running => RecoveryState::Pending,
                RunStatus::Cancelled | RunStatus::Interrupted => continue,
            };
            dump_states.insert(run.id.clone(), state);
            // Only a single object request establishes a negative result for that object.
            if run.arguments.len() != 2
                || !matches!(run.arguments[0].as_str(), "--virtaddr" | "--physaddr")
            {
                continue;
            }
            let key = (run.evidence_id.clone(), run.arguments.clone());
            if objects
                .get(&key)
                .is_some_and(|r| r.state == RecoveryState::Recovered)
                && state != RecoveryState::Recovered
            {
                continue;
            }
            objects.insert(
                key,
                Recovery {
                    state,
                    run_id: run.id.clone(),
                },
            );
        }
        Ok(Self {
            objects,
            dump_states,
            output_states,
            plugins: document
                .runs
                .iter()
                .map(|r| (r.id.clone(), (r.plugin.clone(), r.evidence_id.clone())))
                .collect(),
        })
    }

    pub fn recovery(&self, record: &StoredRecord, physical: bool) -> Option<&Recovery> {
        let (plugin, evidence) = self.plugins.get(&record.run_id)?;
        let target = FileDumpTarget::from_record(plugin, &record.record)?;
        self.objects
            .get(&(evidence.clone(), target.arguments(physical)))
    }

    pub fn state(&self, record: &StoredRecord, physical: bool) -> RecoveryState {
        if let Some(recovery) = self.recovery(record, physical) {
            return recovery.state;
        }
        let Some((plugin, _)) = self.plugins.get(&record.run_id) else {
            return RecoveryState::Untested;
        };
        if matches!(plugin.as_str(), super::FILES | super::FILE_PATHS)
            && record.record.text("Kind") == "Referenced executable path"
        {
            return RecoveryState::Referenced;
        }
        if plugin == DUMP_FILES {
            let output = record.record.text("File output");
            let output = if output.is_empty() {
                record.record.text("Result")
            } else {
                output
            };
            if !output.is_empty() && !output.starts_with("file.") {
                return RecoveryState::Unavailable;
            }
            if let Some(state) = self.output_states.get(&(record.run_id.clone(), output)) {
                return *state;
            }
            return self
                .dump_states
                .get(&record.run_id)
                .copied()
                .unwrap_or(RecoveryState::Untested);
        }
        if (SOURCES.contains(&plugin.as_str()) || plugin == super::FILES)
            && FileDumpTarget::from_record(plugin, &record.record).is_none()
        {
            RecoveryState::Unsupported
        } else {
            RecoveryState::Untested
        }
    }
}

/// Runs only on query workers. The UI renders the returned state map without I/O.
pub fn filter_entries(
    store: &ResultStore,
    recovery: &RecoveryIndex,
    entries: Vec<TreeEntry>,
    physical: bool,
    show_unavailable: bool,
) -> Result<(Vec<TreeEntry>, HashMap<i64, RecoveryState>), String> {
    let ids: Vec<_> = entries.iter().map(|entry| entry.id).collect();
    let mut states = HashMap::new();
    for ids in ids.chunks(256) {
        for record in store.fetch(ids)? {
            if !pseudo_file(&file_path(&record.record)) {
                states.insert(record.id, recovery.state(&record, physical));
            }
        }
    }
    let entries = entries
        .into_iter()
        .filter(|entry| {
            states
                .get(&entry.id)
                .is_some_and(|state| show_unavailable || !state.unavailable())
        })
        .collect();
    Ok((entries, states))
}

fn candidates(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &str,
    cancel: &AtomicBool,
) -> Result<Vec<StoredRecord>, String> {
    let mut seen = HashSet::new();
    let runs = document
        .runs
        .iter()
        .rev()
        .filter(|r| {
            r.evidence_id == evidence
                && r.status.has_results()
                && r.arguments.is_empty()
                && SOURCES.contains(&r.plugin.as_str())
        })
        .filter(|r| seen.insert(r.plugin.clone()))
        .map(|r| r.id.clone())
        .collect::<Vec<_>>();
    if !seen.contains(SOURCES[0]) {
        return Err("File recovery requires a completed, unfiltered FileScan analysis".into());
    }
    let store = ResultStore::at(directory);
    let ids = store
        .query(&crate::results::Query {
            runs,
            ..Default::default()
        })?
        .ids;
    let mut records = Vec::new();
    for ids in ids.chunks(256) {
        if cancel.load(Ordering::Relaxed) {
            return Err("File recovery cancelled".into());
        }
        records.extend(
            store
                .fetch(ids)?
                .into_iter()
                .filter(|r| !pseudo_file(&file_path(&r.record))),
        );
    }
    Ok(records)
}

pub fn recovery_runs(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &Evidence,
    engine: &Installation,
    arguments: &[String],
) -> Result<Vec<Run>, String> {
    let physical = physical_offset(arguments)?;
    let mut seen = HashSet::new();
    let mut runs = Vec::new();
    let existing: HashSet<_> = document
        .runs
        .iter()
        .filter(|r| {
            r.evidence_id == evidence.id
                && r.plugin == DUMP_FILES
                && matches!(
                    r.status,
                    RunStatus::Completed
                        | RunStatus::Warning
                        | RunStatus::Queued
                        | RunStatus::Running
                )
        })
        .map(|r| r.arguments.clone())
        .collect();
    let sources: HashMap<_, _> = document
        .runs
        .iter()
        .map(|r| (r.id.as_str(), r.plugin.as_str()))
        .collect();
    for record in candidates(directory, document, &evidence.id, &AtomicBool::new(false))? {
        let source = sources
            .get(record.run_id.as_str())
            .ok_or("Missing file source")?;
        let Some(target) = FileDumpTarget::from_record(source, &record.record) else {
            continue;
        };
        let args = target.arguments(physical);
        if !seen.insert(args.clone()) || existing.contains(&args) {
            continue;
        }
        runs.push(engine.prepare(evidence, DUMP_FILES, args, &directory.join("analyses"))?);
    }
    runs.push(super::prepare(evidence, super::FILES, arguments.to_vec())?);
    Ok(runs)
}

pub(super) fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    let physical = physical_offset(&run.arguments)?;
    let mut inputs = document.clone();
    if let Some(index) = inputs.runs.iter().position(|r| r.id == run.id) {
        inputs.runs.truncate(index);
    }
    let document = &inputs;
    let recovery = RecoveryIndex::load(directory, document)?;
    let mut rows = Vec::new();
    let mut recovered = 0;
    let sources: HashMap<_, _> = document
        .runs
        .iter()
        .map(|r| (r.id.as_str(), r.plugin.as_str()))
        .collect();
    for candidate in candidates(directory, document, &run.evidence_id, cancel)? {
        if cancel.load(Ordering::Relaxed) {
            return Err("File recovery cancelled".into());
        }
        let state = recovery.state(&candidate, physical);
        recovered += usize::from(state == RecoveryState::Recovered);
        let source = *sources
            .get(candidate.run_id.as_str())
            .ok_or("Missing file source")?;
        let mut row = candidate.record.clone();
        if source == SOURCES[0]
            && !row.fields.contains_key("Offset(V)")
            && !row.fields.contains_key("Offset(P)")
            && let Some(offset) = row.fields.get("Offset").cloned()
        {
            row.fields.insert(
                if physical { "Offset(P)" } else { "Offset(V)" }.into(),
                offset,
            );
        }
        row.fields.insert("Source plugin".into(), source.into());
        row.fields
            .insert("Source run".into(), candidate.run_id.clone().into());
        row.fields.insert("Source row".into(), candidate.row.into());
        row.fields
            .insert("Recovery status".into(), state.label().into());
        if let Some(dump) = recovery.recovery(&candidate, physical) {
            row.fields
                .insert("Extraction run".into(), dump.run_id.clone().into());
        }
        rows.push(row);
        if rows.len() % 256 == 0 {
            progress(format!("Indexed {} file objects", rows.len()));
        }
    }
    let mut message = format!(
        "Recovered cached contents for {recovered} of {} file objects. Recovered files may be partial. Source run and row identify each original observation.",
        rows.len()
    );
    let evidence = document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    let references = paths::scan(&evidence.path, cancel, progress)?;
    message.push_str(&format!(
        " Found {} executable path references in the evidence bytes. References do not establish file presence, recoverability, or maliciousness.",
        references.len()
    ));
    let mut warnings = Vec::new();
    if references.len() >= paths::MAX_PATHS {
        warnings.push("Executable path reference limit reached. Narrow the evidence input to complete coverage.".into());
    }
    rows.extend(references);
    Ok((super::table(rows).with_warnings(warnings), message))
}

/// One streaming read of the evidence, independent of inventories and extraction.
pub(super) fn path_references(
    path: &Path,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    let rows = paths::scan(path, cancel, progress)?;
    let message = format!(
        "Found {} executable path references in the evidence bytes. References do not establish file presence, recoverability, or maliciousness. No file contents were extracted.",
        rows.len()
    );
    let mut warnings = Vec::new();
    if rows.len() >= paths::MAX_PATHS {
        warnings.push("Executable path reference limit reached. Narrow the evidence input to complete coverage.".into());
    }
    Ok((super::table(rows).with_warnings(warnings), message))
}
