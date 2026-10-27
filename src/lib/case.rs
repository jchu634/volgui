// Persists case metadata, evidence, runs, and bookmarks.
use std::{
    collections::BTreeSet,
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
use crate::{artifacts::OperatingSystem, results::ResultStore};

#[path = "case/persistence.rs"]
mod persistence;
#[path = "case/rescan.rs"]
mod rescan;
pub use persistence::SaveCheckpoint;

pub type Result<T> = std::result::Result<T, String>;
pub use crate::database::DATABASE;

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
    /// Results are available, but completing coverage requires a change to inputs or scope.
    Warning,
    Failed,
    Cancelled,
    Interrupted,
}

impl RunStatus {
    pub fn can_retry(self) -> bool {
        matches!(self, Self::Failed | Self::Interrupted | Self::Cancelled)
    }

    /// Completed and active runs require an override in the analysis chooser.
    pub fn blocks_plugin_selection(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Running | Self::Completed | Self::Warning
        )
    }

    pub fn has_results(self) -> bool {
        matches!(self, Self::Completed | Self::Warning)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::Completed => "Completed",
            Self::Warning => "Warning",
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
pub struct CaseSnapshot {
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
    Failed,
    Finished,
}

impl QueueClearScope {
    pub fn includes(self, status: RunStatus) -> bool {
        match self {
            Self::Completed => matches!(status, RunStatus::Completed | RunStatus::Cancelled),
            Self::Failed => matches!(status, RunStatus::Failed | RunStatus::Interrupted),
            Self::Finished => !matches!(status, RunStatus::Queued | RunStatus::Running),
        }
    }
}

pub struct Case {
    pub directory: PathBuf,
    pub document: CaseSnapshot,
    _lock: File,
    saves: Option<persistence::BackgroundSaves>,
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
    /// Create a case at an explicit path. The UI uses create_named instead.
    pub fn create(directory: &Path, name: &str) -> Result<Self> {
        if name.trim().is_empty() {
            return Err("Enter a case name".into());
        }
        if directory.exists()
            && fs::read_dir(directory)
                .map_err(|e| e.to_string())?
                .next()
                .is_some()
        {
            return Err("Choose an empty directory for a new case".into());
        }
        fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        let lock = lock_case(directory)?;
        let mut case = Self {
            directory: directory.canonicalize().map_err(|e| e.to_string())?,
            _lock: lock,
            saves: None,
            document: CaseSnapshot {
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

    pub fn create_named(parent: &Path, name: &str) -> Result<Self> {
        let name = Self::validate_name(name)?;
        fs::create_dir_all(parent).map_err(|e| format!("Cannot create case location: {e}"))?;
        let parent = parent
            .canonicalize()
            .map_err(|e| format!("Choose an existing case directory: {e}"))?;
        if !parent.is_dir() {
            return Err("Choose a directory for the case location".into());
        }
        let directory = parent.join(&name);
        fs::create_dir(&directory)
            .map_err(|e| format!("Cannot create case folder {}: {e}", directory.display()))?;
        Self::create(&directory, &name)
    }

    pub fn validate_name(name: &str) -> Result<String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("Enter a case name".into());
        }
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name == "."
            || name == ".."
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
            || [
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9",
            ]
            .contains(&stem.as_str())
        {
            return Err("Use a case name that is a valid folder name".into());
        }
        Ok(name.into())
    }

    pub fn open(path: &Path) -> Result<Self> {
        let database = if path.is_dir() {
            path.join(DATABASE)
        } else {
            path.to_owned()
        };
        if database.file_name().is_none_or(|n| n != DATABASE) {
            return Err(
                "Open case.sqlite from a new-format case. Legacy cases are not supported.".into(),
            );
        }
        let database = database
            .canonicalize()
            .map_err(|e| format!("Cannot open case database: {e}"))?;
        let directory = database
            .parent()
            .ok_or("Case database has no parent")?
            .to_owned();
        // Validate the format before touching a legacy case directory.
        crate::database::connect(&directory)?;
        let lock = lock_case(&directory)?;
        ResultStore::open(&directory)?;
        let mut case = Self {
            document: CaseSnapshot::load(&directory)?,
            directory,
            _lock: lock,
            saves: None,
        };
        let mut changed = false;
        for run in &mut case.document.runs {
            if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                run.status = RunStatus::Interrupted;
                run.finished_at = Some(now());
                run.message = "Application closed before this analysis finished. Rerun to start a new analysis.".into();
                changed = true;
            } else if run.status == RunStatus::Completed
                && run.plugin == crate::analysis::NETWORK_ATTRIBUTION
                && run
                    .message
                    .contains("Stopped at the byte or finding limit.")
            {
                // Earlier versions recorded these partial results as successful.
                run.status = RunStatus::Warning;
                run.message.push_str(" Coverage is incomplete. Narrow the scope with --pid or change the scan limits before running again.");
                changed = true;
            }
        }
        if changed {
            case.save()?;
        }
        Ok(case)
    }

    /// Persist the snapshot in one SQLite transaction, or enqueue it after
    /// enable_background_saves. Poll asynchronous failures with poll_save and
    /// use save_checkpoint before work that requires durable metadata.
    /// Binary and finding rows belong to ingestion and are never replaced here.
    pub fn save(&mut self) -> Result<()> {
        let previous = self.document.updated_at.clone();
        self.document.updated_at = now();
        let result = match &mut self.saves {
            Some(saves) => saves.save(&self.document),
            None => (|| {
                let db = crate::database::connect(&self.directory)?;
                let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
                self.document.persist(tx)
            })(),
        };
        if result.is_err() {
            self.document.updated_at = previous;
        }
        result
    }

    /// Desktop callers enqueue snapshots instead of waiting for SQLite's writer.
    /// Check poll_save for failures; CLI callers keep synchronous save semantics.
    pub fn enable_background_saves(&mut self) -> Result<()> {
        if self.saves.is_none() {
            self.saves = Some(persistence::BackgroundSaves::start(self.directory.clone())?);
        }
        Ok(())
    }

    pub fn poll_save(&mut self) -> Option<Result<()>> {
        self.saves.as_mut()?.poll()
    }

    pub fn has_unsaved_changes(&self) -> bool {
        self.saves
            .as_ref()
            .is_some_and(|saves| saves.has_unsaved_changes())
    }

    pub fn save_checkpoint(&self) -> Result<SaveCheckpoint> {
        match &self.saves {
            Some(saves) => saves.checkpoint(),
            None => Ok(SaveCheckpoint::completed()),
        }
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

    pub fn remove_queue_run(&mut self, id: &str) -> Result<()> {
        let removable = self.document.queue_runs().any(|run| {
            run.id == id && !matches!(run.status, RunStatus::Running | RunStatus::Queued)
        });
        if !removable {
            return Ok(());
        }
        let previous_updated_at = self.document.updated_at.clone();
        self.document.cleared_queue_runs.insert(id.to_string());
        if let Err(error) = self.save() {
            self.document.cleared_queue_runs.remove(id);
            self.document.updated_at = previous_updated_at;
            return Err(error);
        }
        Ok(())
    }

    pub fn finish(&mut self, id: &str, outcome: &Outcome) -> Result<()> {
        if !self.document.runs.iter().any(|run| run.id == id) {
            return Err("Unknown analysis".into());
        }
        crate::object_store::ObjectStore::at(&self.directory)
            .capture_run(id, &AtomicBool::new(false))?;
        self.finish_recorded(id, outcome)
    }

    /// Complete metadata after the worker has archived outputs and imported
    /// findings. This path performs no binary IO on the UI thread.
    pub fn finish_recorded(&mut self, id: &str, outcome: &Outcome) -> Result<()> {
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
        let mut completion = Outcome {
            status: outcome.status,
            exit_code: outcome.exit_code,
            message: outcome.message.clone(),
            table: None,
        };
        if let Some(table) = &outcome.table {
            for warning in &table.warnings {
                completion.warn(warning);
            }
        }
        completion.check_output_coverage(&self.run_dir(id))?;
        let count = if completion.status.has_results() {
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
        run.status = completion.status;
        run.exit_code = outcome.exit_code;
        run.finished_at = Some(now());
        run.message = completion.message;
        run.row_count = count;
        self.save()
    }

    pub fn results(&self, id: &str) -> Result<Table> {
        if !self.document.runs.iter().any(|r| r.id == id) {
            return Err("Unknown analysis".into());
        }
        let store = ResultStore::at(&self.directory);
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

impl CaseSnapshot {
    /// Read the authoritative database. This value is a UI/query snapshot only.
    pub fn load(directory: &Path) -> Result<Self> {
        let db = crate::database::connect(directory)?;
        let (name, created_at, updated_at) = db
            .query_row(
                "SELECT name,created_at,updated_at FROM case_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| format!("Cannot read case metadata: {e}"))?;
        let mut evidence = Vec::new();
        let mut statement = db.prepare("SELECT id,path,size,modified_ns,sha256,added_at,verification_json,operating_system FROM evidence ORDER BY rowid").map_err(|e|e.to_string())?;
        let mut rows = statement.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let get = |i| r.get::<_, String>(i).map_err(|e| e.to_string());
            evidence.push(Evidence {
                id: get(0)?,
                path: get(1)?.into(),
                size: r.get::<_, i64>(2).map_err(|e| e.to_string())? as u64,
                modified_ns: r
                    .get::<_, Option<String>>(3)
                    .map_err(|e| e.to_string())?
                    .map(|s| s.parse::<u128>().map_err(|e| e.to_string()))
                    .transpose()?,
                sha256: get(4)?,
                added_at: get(5)?,
                verification: r
                    .get::<_, Option<String>>(6)
                    .map_err(|e| e.to_string())?
                    .map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
                    .transpose()?,
                operating_system: serde_json::from_str(&get(7)?).map_err(|e| e.to_string())?,
            });
        }
        let mut runs = Vec::new();
        let mut cleared_queue_runs = BTreeSet::new();
        let mut statement = db.prepare("SELECT r.id,evidence_id,plugin,arguments_json,command_json,engine_version,created_at,started_at,finished_at,status,exit_code,message,queue_hidden,COALESCE((SELECT row_count FROM scans WHERE run_id=r.id),0) FROM analysis_runs r ORDER BY r.rowid").map_err(|e|e.to_string())?;
        let mut rows = statement.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let get = |i| r.get::<_, String>(i).map_err(|e| e.to_string());
            let id = get(0)?;
            if r.get::<_, bool>(12).map_err(|e| e.to_string())? {
                cleared_queue_runs.insert(id.clone());
            }
            runs.push(Run {
                id,
                evidence_id: get(1)?,
                plugin: get(2)?,
                arguments: serde_json::from_str(&get(3)?).map_err(|e| e.to_string())?,
                command: serde_json::from_str(&get(4)?).map_err(|e| e.to_string())?,
                engine_version: get(5)?,
                created_at: get(6)?,
                started_at: r.get(7).map_err(|e| e.to_string())?,
                finished_at: r.get(8).map_err(|e| e.to_string())?,
                status: serde_json::from_str(&get(9)?).map_err(|e| e.to_string())?,
                exit_code: r.get(10).map_err(|e| e.to_string())?,
                message: get(11)?,
                row_count: r.get::<_, i64>(13).map_err(|e| e.to_string())? as usize,
            });
        }
        let mut statement = db.prepare("SELECT run_id,row_index,bookmarked,note FROM annotations ORDER BY run_id,row_index").map_err(|e|e.to_string())?;
        let annotations = statement
            .query_map([], |r| {
                Ok(Annotation {
                    run_id: r.get(0)?,
                    row: r.get::<_, i64>(1)? as usize,
                    bookmarked: r.get(2)?,
                    note: r.get(3)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            name,
            created_at,
            updated_at,
            evidence,
            runs,
            annotations,
            cleared_queue_runs,
        })
    }
    pub fn queue_runs(&self) -> impl DoubleEndedIterator<Item = &Run> {
        self.runs.iter().filter(|run| {
            matches!(run.status, RunStatus::Queued | RunStatus::Running)
                || !self.cleared_queue_runs.contains(&run.id)
        })
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
                name.eq_ignore_ascii_case(DATABASE)
                    || name.eq_ignore_ascii_case(".volgui.lock")
                    || name.to_ascii_lowercase().starts_with(DATABASE)
            })
            || canonical.starts_with(directory.join("analyses"))
            || canonical.starts_with(directory.join("objects"))
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
        html.push_str("</table><h2>Managed binary outputs</h2><table><tr><th>Analysis / logical name</th><th>Bytes</th><th>SHA-256</th><th>Availability</th></tr>");
        let db = crate::database::connect(directory)?;
        let mut statement = db.prepare("SELECT run_id,name,size,sha256,blocked_reason FROM analysis_outputs ORDER BY run_id,name").map_err(|e|e.to_string())?;
        let mut outputs = statement.query([]).map_err(|e| e.to_string())?;
        while let Some(output) = outputs.next().map_err(|e| e.to_string())? {
            let run: String = output.get(0).map_err(|e| e.to_string())?;
            let name: String = output.get(1).map_err(|e| e.to_string())?;
            let size: Option<i64> = output.get(2).map_err(|e| e.to_string())?;
            let sha: Option<String> = output.get(3).map_err(|e| e.to_string())?;
            let blocked: Option<String> = output.get(4).map_err(|e| e.to_string())?;
            html.push_str(&format!(
                "<tr><td>{}<br>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&run),
                escape_html(&name),
                size.map(|n| n.to_string()).unwrap_or_default(),
                escape_html(sha.as_deref().unwrap_or("No stored content")),
                escape_html(
                    blocked
                        .as_deref()
                        .unwrap_or("Stored; integrity checked when read")
                )
            ));
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

// Drain accepted saves before releasing the exclusive case lock on shutdown.
impl Drop for Case {
    fn drop(&mut self) {
        self.saves.take();
    }
}

impl CaseSnapshot {
    fn persist(&self, tx: rusqlite::Transaction<'_>) -> Result<()> {
        tx.execute("INSERT INTO case_meta VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET name=excluded.name,updated_at=excluded.updated_at",
            rusqlite::params![self.name,self.created_at,self.updated_at]).map_err(|e|e.to_string())?;
        for e in &self.evidence {
            tx.execute("INSERT INTO evidence VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET verification_json=excluded.verification_json,modified_ns=excluded.modified_ns,operating_system=excluded.operating_system",
                rusqlite::params![e.id,e.path.to_str().ok_or("Evidence path is not UTF-8")?,e.size as i64,e.modified_ns.map(|n|n.to_string()),e.sha256,e.added_at,e.verification.as_ref().map(serde_json::to_string).transpose().map_err(|e|e.to_string())?,serde_json::to_string(&e.operating_system).map_err(|e|e.to_string())?]).map_err(|e|e.to_string())?;
        }
        for r in &self.runs {
            // Only an unstarted application placeholder can resolve its arguments
            // in place. Executed commands and source IDs remain immutable.
            tx.execute("INSERT INTO analysis_runs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(id) DO UPDATE SET arguments_json=CASE WHEN analysis_runs.plugin=?14 AND analysis_runs.message=?15 AND analysis_runs.started_at IS NULL THEN excluded.arguments_json ELSE analysis_runs.arguments_json END,command_json=CASE WHEN analysis_runs.plugin=?14 AND analysis_runs.message=?15 AND analysis_runs.started_at IS NULL THEN excluded.command_json ELSE analysis_runs.command_json END,started_at=excluded.started_at,finished_at=excluded.finished_at,status=excluded.status,exit_code=excluded.exit_code,message=excluded.message,queue_hidden=excluded.queue_hidden",
                rusqlite::params![r.id,r.evidence_id,r.plugin,serde_json::to_string(&r.arguments).map_err(|e|e.to_string())?,serde_json::to_string(&r.command).map_err(|e|e.to_string())?,r.engine_version,r.created_at,r.started_at,r.finished_at,serde_json::to_string(&r.status).map_err(|e|e.to_string())?,r.exit_code,r.message,self.cleared_queue_runs.contains(&r.id),crate::analysis::APPLICATION,crate::analyses::APPLICATION_RECOVERY_PENDING]).map_err(|e|e.to_string())?;
        }
        // Deferred recovery inserts prerequisite jobs before an existing parser.
        // Run IDs are stable foreign keys; rowid is only the persisted queue order.
        let stored_order = tx
            .prepare("SELECT id FROM analysis_runs ORDER BY rowid")
            .map_err(|e| e.to_string())?
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if !stored_order.iter().eq(self.runs.iter().map(|run| &run.id)) {
            let mut position: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(rowid),0) FROM analysis_runs",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            for run in &self.runs {
                position = position
                    .checked_add(1)
                    .ok_or("Analysis queue order exceeds SQLite limits")?;
                tx.execute(
                    "UPDATE analysis_runs SET rowid=?1 WHERE id=?2",
                    rusqlite::params![position, run.id],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        tx.execute("DELETE FROM annotations", [])
            .map_err(|e| e.to_string())?;
        for a in &self.annotations {
            tx.execute(
                "INSERT INTO annotations VALUES(?1,?2,?3,?4)",
                rusqlite::params![a.run_id, a.row as i64, a.bookmarked, a.note],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }
}
