//! Rebuild a case from saved scan requests, retaining a standalone backup.
use super::*;
use crate::{analyses::AnalysisDraft, volatility::Installation};
use rusqlite::{
    Connection,
    backup::{Backup, StepResult},
};

impl Case {
    /// Run on a worker with exclusive ownership of an idle case. The live
    /// database changes only after preparation and backup both succeed.
    pub fn rescan(&mut self, engine: &Installation, cancel: &AtomicBool) -> Result<PathBuf> {
        if self.document.runs.is_empty() {
            return Err("There are no previous analyses to rescan".into());
        }
        if self
            .document
            .runs
            .iter()
            .any(|run| matches!(run.status, RunStatus::Queued | RunStatus::Running))
        {
            return Err("Finish or cancel queued and running analyses before rescanning".into());
        }
        check_cancel(cancel)?;
        let staging = tempfile::Builder::new()
            .prefix(".rescan-")
            .tempdir_in(&self.directory)
            .map_err(|e| e.to_string())?;
        let mut fresh = Case {
            directory: staging.path().to_owned(),
            document: self.document.clone(),
            _lock: lock_case(staging.path())?,
            saves: None,
        };
        ResultStore::open(&fresh.directory)?;
        fresh.document.runs.clear();
        fresh.document.annotations.clear();
        fresh.document.cleared_queue_runs.clear();

        // Replay each distinct request once. Engine jobs precede native reports
        // so reports bind to fresh inputs rather than saved source run IDs.
        let mut seen = BTreeSet::new();
        let mut engine_runs = Vec::new();
        for previous in &self.document.runs {
            check_cancel(cancel)?;
            if crate::analysis::is_native(&previous.plugin) {
                continue;
            }
            if !seen.insert((
                previous.evidence_id.clone(),
                previous.plugin.clone(),
                previous.arguments.clone(),
            )) {
                continue;
            }
            let evidence = self
                .document
                .evidence
                .iter()
                .find(|e| e.id == previous.evidence_id)
                .ok_or("Evidence is no longer available")?;
            engine_runs.push(
                engine
                    .prepare(
                        evidence,
                        &previous.plugin,
                        previous.arguments.clone(),
                        &self.directory.join("analyses"),
                    )
                    .map_err(|e| format!("{}: {e}", previous.plugin))?,
            );
        }
        if !engine_runs.is_empty() {
            fresh.queue_batch(engine_runs)?;
        }
        for previous in &self.document.runs {
            check_cancel(cancel)?;
            if !crate::analysis::is_native(&previous.plugin) {
                continue;
            }
            if crate::analysis::quarantine::is_passive(previous) {
                continue;
            }
            let arguments = if previous.plugin == crate::analysis::APPLICATION {
                crate::analysis::application::user_arguments(&previous.arguments)?
            } else {
                previous.arguments.clone()
            };
            if !seen.insert((
                previous.evidence_id.clone(),
                previous.plugin.clone(),
                arguments.clone(),
            )) {
                continue;
            }
            let evidence = self
                .document
                .evidence
                .iter()
                .find(|e| e.id == previous.evidence_id)
                .ok_or("Evidence is no longer available")?;
            let mut runs = if previous.plugin == crate::analysis::STRINGS {
                vec![crate::analysis::prepare(
                    evidence,
                    &previous.plugin,
                    arguments,
                )?]
            } else {
                let mut draft = AnalysisDraft::new(evidence);
                draft.selected.insert(previous.plugin.clone());
                draft.arguments.insert(
                    previous.plugin.clone(),
                    crate::volatility::format_arguments(&arguments),
                );
                draft
                    .prepare_in_case(engine, evidence, &fresh)
                    .map_err(|e| format!("{}: {e}", previous.plugin))?
            };
            // Preparation uses the staging case to resolve dependencies, while
            // engine captures must target the live case after publication.
            for run in &mut runs {
                if !crate::analysis::is_native(&run.plugin) {
                    *run = engine.prepare(
                        evidence,
                        &run.plugin,
                        run.arguments.clone(),
                        &self.directory.join("analyses"),
                    )?;
                }
            }
            fresh.queue_batch(runs)?;
        }

        self.save_checkpoint()?.wait(cancel)?;
        // Drain the save worker before replacing its database, so an old
        // snapshot cannot restore the previous runs after the rebuild.
        self.saves.take();
        self.save()?;
        let backups = self.directory.join("backups");
        fs::create_dir_all(&backups).map_err(|e| e.to_string())?;
        let backup = tempfile::Builder::new()
            .prefix(&format!("rescan-{}-", Utc::now().format("%Y%m%d-%H%M%S")))
            .tempdir_in(backups)
            .map_err(|e| e.to_string())?;
        let mut live = crate::database::connect(&self.directory)?;
        let mut backup_db =
            Connection::open(backup.path().join(DATABASE)).map_err(|e| e.to_string())?;
        copy_database(&live, &mut backup_db, cancel)?;
        drop(backup_db);
        for name in ["objects", "analyses"] {
            let source = self.directory.join(name);
            if source.exists() {
                copy_directory(&source, &backup.path().join(name), cancel)?;
            }
        }
        check_cancel(cancel)?;
        let source = crate::database::connect(&fresh.directory)?;
        // The pack remains in place. Retain its immutable catalog so rescans
        // can reuse identical chunks without appending all the old bytes again.
        source
            .execute(
                "ATTACH DATABASE ?1 AS previous",
                [self
                    .directory
                    .join(DATABASE)
                    .to_str()
                    .ok_or("Case path is not UTF-8")?],
            )
            .map_err(|e| e.to_string())?;
        source
            .execute_batch(
                "BEGIN IMMEDIATE;
            INSERT INTO binary_chunks SELECT * FROM previous.binary_chunks;
            INSERT INTO binary_objects SELECT * FROM previous.binary_objects;
            COMMIT;
            DETACH DATABASE previous;",
            )
            .map_err(|e| e.to_string())?;
        // Keep the complete backup before publishing. SQLite rolls back an
        // incomplete backup operation, including cancellation or lock errors.
        let backup_path = backup.keep();
        copy_database(&source, &mut live, cancel)
            .map_err(|e| format!("{e}. Original case backup: {}", backup_path.display()))?;
        self.document = fresh.document.clone();
        Ok(backup_path)
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err("Case rescan cancelled".into())
    } else {
        Ok(())
    }
}

fn copy_database(
    source: &Connection,
    destination: &mut Connection,
    cancel: &AtomicBool,
) -> Result<()> {
    let backup = Backup::new(source, destination).map_err(|e| e.to_string())?;
    loop {
        check_cancel(cancel)?;
        match backup.step(256).map_err(|e| e.to_string())? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            _ => return Err("Case database is busy; try rescanning again".into()),
        }
    }
}

fn copy_directory(source: &Path, destination: &Path, cancel: &AtomicBool) -> Result<()> {
    fs::create_dir(destination).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        check_cancel(cancel)?;
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &target, cancel)?;
        } else if kind.is_file() {
            let mut input = File::open(entry.path()).map_err(|e| e.to_string())?;
            let mut output = File::create(target).map_err(|e| e.to_string())?;
            let mut buffer = vec![0; 1024 * 1024];
            loop {
                check_cancel(cancel)?;
                let size = input.read(&mut buffer).map_err(|e| e.to_string())?;
                if size == 0 {
                    break;
                }
                output
                    .write_all(&buffer[..size])
                    .map_err(|e| e.to_string())?;
            }
            output.sync_all().map_err(|e| e.to_string())?;
        } else {
            return Err(format!(
                "Cannot back up unsupported file: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}
