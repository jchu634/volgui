use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::UNIX_EPOCH,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::volatility::{Outcome, Table};
use crate::{
    artifacts::OperatingSystem,
    results::{DATABASE, ResultStore},
};

pub type Result<T> = std::result::Result<T, String>;
pub const MANIFEST: &str = "case.volgui.json";

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or("File has no parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut temp, value).map_err(|e| e.to_string())?;
    temp.write_all(b"\n").map_err(|e| e.to_string())?;
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    temp.persist(path)
        .map_err(|e| format!("Could not save {}: {e}", path.display()))?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub path: PathBuf,
    pub size: u64,
    pub modified_ns: Option<u128>,
    pub sha256: String,
    pub added_at: String,
    #[serde(default)]
    pub verification: Option<Verification>,
    #[serde(default)]
    pub operating_system: OperatingSystem,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verification {
    pub checked_at: String,
    pub sha256: String,
    pub matches: bool,
}

impl Evidence {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }

    pub fn inspect(
        path: &Path,
        cancel: &AtomicBool,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<Self> {
        let path = path
            .canonicalize()
            .map_err(|e| format!("Cannot open evidence: {e}"))?;
        let mut file = File::open(&path).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file() || before.len() == 0 {
            return Err("Choose a nonempty memory image file".into());
        }
        let modified = |m: &fs::Metadata| {
            m.modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|t| t.as_nanos())
        };
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        let mut read = 0;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Evidence operation cancelled".into());
            }
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            read += count as u64;
            progress(read, before.len());
        }
        let after = file.metadata().map_err(|e| e.to_string())?;
        if before.len() != after.len()
            || modified(&before) != modified(&after)
            || read != before.len()
        {
            return Err("Evidence changed while hashing. Import a stable acquisition.".into());
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            path,
            size: read,
            modified_ns: modified(&after),
            sha256: format!("{:x}", hash.finalize()),
            added_at: now(),
            verification: None,
            operating_system: OperatingSystem::Unknown,
        })
    }

    pub fn check_metadata(&self) -> Result<()> {
        if self.verification.as_ref().is_some_and(|v| !v.matches) {
            return Err("Evidence failed its last integrity check. Restore the original acquisition and verify it again.".into());
        }
        let metadata =
            fs::metadata(&self.path).map_err(|e| format!("Evidence is unavailable: {e}"))?;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|t| t.as_nanos());
        if metadata.len() != self.size || modified != self.modified_ns {
            return Err(
                "Evidence size or modification time changed. Verify its SHA-256 before analysis."
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

impl RunStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
            Self::Interrupted => "Interrupted",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    pub evidence_id: String,
    pub plugin: String,
    pub arguments: Vec<String>,
    pub command: Vec<String>,
    pub engine_version: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub status: RunStatus,
    pub exit_code: Option<i32>,
    pub row_count: usize,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Annotation {
    pub run_id: String,
    pub row: usize,
    pub bookmarked: bool,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseDocument {
    pub schema_version: u32,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub evidence: Vec<Evidence>,
    pub runs: Vec<Run>,
    pub annotations: Vec<Annotation>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub cleared_queue_runs: BTreeSet<String>,
}

#[derive(Clone, Copy)]
pub enum QueueClearScope {
    Completed,
    Finished,
}

impl QueueClearScope {
    pub fn includes(self, status: RunStatus) -> bool {
        match self {
            Self::Completed => matches!(status, RunStatus::Completed | RunStatus::Cancelled),
            Self::Finished => !matches!(status, RunStatus::Queued | RunStatus::Running),
        }
    }
}

pub struct Case {
    pub directory: PathBuf,
    pub document: CaseDocument,
    _lock: File,
}

fn lock_case(directory: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".volgui.lock"))
        .map_err(|e| format!("Cannot lock case directory: {e}"))?;
    lock.try_lock().map_err(|e| {
        format!("Case is already open in another application, or cannot be locked: {e}")
    })?;
    Ok(lock)
}

impl Case {
    pub fn create(directory: &Path, name: &str) -> Result<Self> {
        if name.trim().is_empty() {
            return Err("Enter a case name".into());
        }
        fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        let lock = lock_case(directory)?;
        if directory.join(MANIFEST).exists() {
            return Err("This directory already contains a case. Open it instead.".into());
        }
        let mut case = Self {
            directory: directory.canonicalize().map_err(|e| e.to_string())?,
            _lock: lock,
            document: CaseDocument {
                schema_version: 1,
                name: name.trim().into(),
                created_at: now(),
                updated_at: now(),
                evidence: vec![],
                runs: vec![],
                annotations: vec![],
                cleared_queue_runs: BTreeSet::new(),
            },
        };
        ResultStore::open(&case.directory)?;
        case.save()?;
        Ok(case)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let manifest = if path.is_dir() {
            path.join(MANIFEST)
        } else {
            path.to_owned()
        };
        let manifest = manifest
            .canonicalize()
            .map_err(|e| format!("Cannot open case: {e}"))?;
        let lock = lock_case(manifest.parent().unwrap())?;
        let document: CaseDocument =
            serde_json::from_reader(File::open(&manifest).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Invalid case file: {e}"))?;
        if document.schema_version != 1 {
            return Err("Unsupported case format version".into());
        }
        let mut ids = HashSet::new();
        for id in document
            .evidence
            .iter()
            .map(|e| &e.id)
            .chain(document.runs.iter().map(|r| &r.id))
        {
            if Uuid::parse_str(id).is_err() || !ids.insert(id.clone()) {
                return Err("Invalid or duplicate case identifier".into());
            }
        }
        if document
            .runs
            .iter()
            .any(|r| !document.evidence.iter().any(|e| e.id == r.evidence_id))
        {
            return Err("Analysis references missing evidence".into());
        }
        if document.annotations.iter().any(|a| {
            !document
                .runs
                .iter()
                .any(|r| r.id == a.run_id && a.row < r.row_count)
        }) {
            return Err("Annotation references a missing artifact".into());
        }
        let mut case = Self {
            directory: manifest.parent().unwrap().to_owned(),
            document,
            _lock: lock,
        };
        ResultStore::open(&case.directory)?;
        for evidence in &mut case.document.evidence {
            if evidence.operating_system == OperatingSystem::Unknown {
                evidence.operating_system = case
                    .document
                    .runs
                    .iter()
                    .rev()
                    .filter(|r| r.evidence_id == evidence.id)
                    .map(|r| OperatingSystem::for_plugin(&r.plugin))
                    .find(|os| *os != OperatingSystem::Unknown)
                    .unwrap_or_default();
            }
        }
        let mut changed = false;
        for run in &mut case.document.runs {
            if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                run.status = RunStatus::Interrupted;
                run.finished_at = Some(now());
                run.message = "Application closed before this analysis finished. Rerun to start a new analysis.".into();
                changed = true;
            }
        }
        if changed {
            case.save()?;
        }
        Ok(case)
    }

    pub fn save(&mut self) -> Result<()> {
        self.document.updated_at = now();
        atomic_json(&self.directory.join(MANIFEST), &self.document)
    }

    pub fn add_evidence(&mut self, evidence: Evidence) -> Result<()> {
        if self
            .document
            .evidence
            .iter()
            .any(|e| e.path == evidence.path)
        {
            return Err("This evidence file is already in the case".into());
        }
        self.document.evidence.push(evidence);
        if let Err(error) = self.save() {
            self.document.evidence.pop();
            return Err(error);
        }
        Ok(())
    }

    pub fn record_verification(&mut self, id: &str, current: &Evidence) -> Result<bool> {
        let evidence = self
            .document
            .evidence
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or("Unknown evidence")?;
        let matches = evidence.sha256 == current.sha256 && evidence.size == current.size;
        evidence.verification = Some(Verification {
            checked_at: now(),
            sha256: current.sha256.clone(),
            matches,
        });
        if matches {
            evidence.modified_ns = current.modified_ns;
        }
        self.save()?;
        Ok(matches)
    }

    pub fn queue(&mut self, run: Run) -> Result<()> {
        self.queue_batch(vec![run])
    }

    pub fn queue_batch(&mut self, runs: Vec<Run>) -> Result<()> {
        let mut ids: std::collections::HashSet<_> =
            self.document.runs.iter().map(|r| r.id.as_str()).collect();
        if runs.is_empty()
            || runs.iter().any(|run| {
                Uuid::parse_str(&run.id).is_err()
                    || !ids.insert(&run.id)
                    || !self
                        .document
                        .evidence
                        .iter()
                        .any(|e| e.id == run.evidence_id)
                    || run.status != RunStatus::Queued
                    || run.command.is_empty()
            })
        {
            return Err("Invalid analysis request".into());
        }
        let previous_len = self.document.runs.len();
        self.document.runs.extend(runs);
        if let Err(error) = self.save() {
            self.document.runs.truncate(previous_len);
            return Err(error);
        }
        Ok(())
    }

    pub fn run_dir(&self, id: &str) -> PathBuf {
        self.directory.join("analyses").join(id)
    }

    /// Dismiss finished queue entries without deleting history, results or output files.
    pub fn clear_queue(&mut self, scope: QueueClearScope) -> Result<usize> {
        let ids: Vec<_> = self
            .document
            .queue_runs()
            .filter(|run| scope.includes(run.status))
            .map(|run| run.id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let previous_updated_at = self.document.updated_at.clone();
        self.document.cleared_queue_runs.extend(ids.iter().cloned());
        if let Err(error) = self.save() {
            for id in &ids {
                self.document.cleared_queue_runs.remove(id);
            }
            self.document.updated_at = previous_updated_at;
            return Err(error);
        }
        Ok(ids.len())
    }

    pub fn finish(&mut self, id: &str, outcome: &Outcome) -> Result<()> {
        let store = ResultStore::at(&self.directory);
        if let Some(table) = &outcome.table {
            let run = self
                .document
                .runs
                .iter()
                .find(|r| r.id == id)
                .ok_or("Unknown analysis")?;
            store.insert(run, table)?;
        }
        let count = if outcome.status == RunStatus::Completed {
            store.count(id)?
        } else {
            0
        };
        let run = self
            .document
            .runs
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or("Unknown analysis")?;
        run.status = outcome.status;
        run.exit_code = outcome.exit_code;
        run.finished_at = Some(now());
        run.message = outcome.message.clone();
        run.row_count = count;
        self.save()
    }

    pub fn results(&self, id: &str) -> Result<Table> {
        if !self.document.runs.iter().any(|r| r.id == id) {
            return Err("Unknown analysis".into());
        }
        let store = ResultStore::at(&self.directory);
        if !store.contains(id)? {
            self.document
                .migrate_results(&self.directory, &AtomicBool::new(false))?;
        }
        store.table(id)
    }

    pub fn annotation(&self, run: &str, row: usize) -> Option<&Annotation> {
        self.document
            .annotations
            .iter()
            .find(|a| a.run_id == run && a.row == row)
    }

    pub fn annotate(
        &mut self,
        run: &str,
        row: usize,
        bookmarked: bool,
        note: String,
    ) -> Result<()> {
        let previous = self.document.annotations.clone();
        if !self
            .document
            .runs
            .iter()
            .any(|r| r.id == run && row < r.row_count)
        {
            return Err("Unknown artifact".into());
        }
        self.document
            .annotations
            .retain(|a| a.run_id != run || a.row != row);
        if bookmarked || !note.is_empty() {
            self.document.annotations.push(Annotation {
                run_id: run.into(),
                row,
                bookmarked,
                note,
            });
        }
        if let Err(error) = self.save() {
            self.document.annotations = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn report(&self) -> Result<String> {
        self.document.report(&self.directory)
    }
}

impl CaseDocument {
    pub fn queue_runs(&self) -> impl DoubleEndedIterator<Item = &Run> {
        self.runs.iter().filter(|run| {
            matches!(run.status, RunStatus::Queued | RunStatus::Running)
                || !self.cleared_queue_runs.contains(&run.id)
        })
    }

    pub fn migrate_results(&self, directory: &Path, cancel: &AtomicBool) -> Result<()> {
        let store = ResultStore::open(directory)?;
        for run in self
            .runs
            .iter()
            .filter(|r| r.status == RunStatus::Completed)
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Case loading cancelled".into());
            }
            if !store.contains(&run.id)? {
                let table =
                    Table::read(&directory.join("analyses").join(&run.id).join("stdout.json"))?;
                store.insert_cancellable(run, &table, cancel)?;
            }
        }
        Ok(())
    }
    pub fn export(&self, directory: &Path, path: &Path, content: &[u8]) -> Result<()> {
        self.export_reader(directory, path, &mut &content[..])
    }

    pub fn export_reader(
        &self,
        directory: &Path,
        path: &Path,
        reader: &mut impl std::io::Read,
    ) -> Result<()> {
        let parent = path
            .parent()
            .ok_or("Export path has no parent")?
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let target = parent.join(path.file_name().ok_or("Export path has no file name")?);
        let canonical = target.canonicalize().unwrap_or_else(|_| target.clone());
        if self
            .evidence
            .iter()
            .any(|e| e.path == canonical || e.path == target)
            || target.file_name().is_some_and(|n| {
                let name = n.to_string_lossy();
                name.eq_ignore_ascii_case(MANIFEST)
                    || name.eq_ignore_ascii_case(".volgui.lock")
                    || name.to_ascii_lowercase().starts_with(DATABASE)
            })
            || canonical.starts_with(directory.join("analyses"))
        {
            return Err(
                "Choose an export path outside original evidence and saved analysis files".into(),
            );
        }
        let mut temp = tempfile::NamedTempFile::new_in(&parent).map_err(|e| e.to_string())?;
        std::io::copy(reader, &mut temp).map_err(|e| e.to_string())?;
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        temp.persist(&target).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn report(&self, directory: &Path) -> Result<String> {
        let mut html = String::from(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>VolGUI case report</title><style>body{font:14px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#17202a}table{width:100%;border-collapse:collapse;margin:16px 0 32px}td,th{border:1px solid #ccc;text-align:left;padding:8px;vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f7;padding:16px}h1,h2{color:#26394d}@media print{pre,tr{break-inside:avoid}}</style>",
        );
        html.push_str(&format!("<h1>{}</h1><p>Exported {} · Created {}</p><h2>Evidence</h2><table><tr><th>Path</th><th>Bytes</th><th>SHA-256</th></tr>", escape_html(&self.name), now(), escape_html(&self.created_at)));
        for e in &self.evidence {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&e.path.display().to_string()),
                e.size,
                escape_html(&e.sha256)
            ));
            if let Some(v) = &e.verification {
                html.push_str(&format!(
                    "<tr><td colspan=\"3\">Verified {} · {} · observed SHA-256 {}</td></tr>",
                    escape_html(&v.checked_at),
                    if v.matches { "MATCH" } else { "MISMATCH" },
                    escape_html(&v.sha256)
                ));
            }
        }
        html.push_str("</table><h2>Analysis history</h2><table><tr><th>Plugin / engine</th><th>Evidence / run ID</th><th>Status / timestamps</th><th>Command / diagnostics</th></tr>");
        for r in &self.runs {
            html.push_str(&format!("<tr><td>{}<br>{}</td><td>{}<br>{}</td><td>{} · {} rows<br>Queued {}<br>Started {}<br>Finished {}<br>Exit {:?}</td><td><pre>{}</pre>{}</td></tr>", escape_html(&r.plugin), escape_html(&r.engine_version), escape_html(&r.evidence_id), r.id, r.status.label(), r.row_count, escape_html(&r.created_at), escape_html(r.started_at.as_deref().unwrap_or("Not started")), escape_html(r.finished_at.as_deref().unwrap_or("Not finished")), r.exit_code, escape_html(&serde_json::to_string(&r.command).unwrap_or_default()), escape_html(&r.message)));
        }
        html.push_str("</table><h2>Bookmarked and annotated artifacts</h2>");
        let store = ResultStore::at(directory);
        for a in &self.annotations {
            if !self.runs.iter().any(|r| r.id == a.run_id) {
                return Err("Unknown annotated analysis".into());
            }
            let row = store
                .record(&a.run_id, a.row)?
                .ok_or("Annotated artifact is missing from its output")?;
            html.push_str(&format!(
                "<h3>{} · row {}{}</h3><p>{}</p><pre>{}</pre>",
                escape_html(&a.run_id),
                a.row + 1,
                if a.bookmarked { " · bookmarked" } else { "" },
                escape_html(&a.note),
                escape_html(
                    &serde_json::to_string_pretty(&row.record.fields).map_err(|e| e.to_string())?
                )
            ));
        }
        html.push_str("<p>Original evidence is referenced, not copied. Hashes reflect import time unless separately verified. Plugin records are observations and require investigator interpretation.</p></html>");
        Ok(html)
    }
}

pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
