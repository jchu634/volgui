//! Ordered desktop snapshot saves. SQLite lock waits never run on the UI thread.
use super::{CaseSnapshot, Result};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

enum Request {
    Save(u64, Box<CaseSnapshot>),
    Checkpoint(Sender<Result<()>>),
    Stop,
}

/// A worker waits here before publishing outputs that reference newly queued runs.
pub struct SaveCheckpoint(Receiver<Result<()>>);

impl SaveCheckpoint {
    pub(super) fn completed() -> Self {
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(Ok(()));
        Self(rx)
    }

    pub fn wait(self, cancel: &AtomicBool) -> Result<()> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Analysis cancelled before case save completed".into());
            }
            match self.0.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => return result,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("Case save worker stopped".into());
                }
            }
        }
    }
}

pub(super) struct BackgroundSaves {
    tx: Sender<Request>,
    results: Receiver<(u64, Result<()>)>,
    worker: Option<JoinHandle<()>>,
    revision: u64,
    persisted: u64,
    disconnected: bool,
}

impl BackgroundSaves {
    pub fn start(directory: PathBuf) -> Result<Self> {
        let (tx, requests) = mpsc::channel();
        let (results_tx, results) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("case-saves".into())
            .spawn(move || {
                let mut last_result = Ok(());
                let mut pending = None;
                loop {
                    let request = pending.take().map(Ok).unwrap_or_else(|| requests.recv());
                    match request {
                        Ok(Request::Save(mut revision, mut document)) => {
                            // A newer complete snapshot includes all older UI edits.
                            // Never coalesce across a worker's durability checkpoint.
                            while let Ok(next) = requests.try_recv() {
                                match next {
                                    Request::Save(next_revision, next_document) => {
                                        revision = next_revision;
                                        document = next_document;
                                    }
                                    next => {
                                        pending = Some(next);
                                        break;
                                    }
                                }
                            }
                            last_result = (|| {
                                let db = crate::database::connect(&directory)?;
                                let tx = crate::database::write_transaction(
                                    &db,
                                    &AtomicBool::new(false),
                                )?;
                                document.persist(tx)
                            })();
                            let _ = results_tx.send((revision, last_result.clone()));
                        }
                        Ok(Request::Checkpoint(reply)) => {
                            let _ = reply.send(last_result.clone());
                        }
                        Ok(Request::Stop) | Err(_) => break,
                    }
                }
            })
            .map_err(|e| format!("Cannot start case save worker: {e}"))?;
        Ok(Self {
            tx,
            results,
            worker: Some(worker),
            revision: 0,
            persisted: 0,
            disconnected: false,
        })
    }

    pub fn save(&mut self, document: &CaseSnapshot) -> Result<()> {
        let revision = self.revision + 1;
        self.tx
            .send(Request::Save(revision, Box::new(document.clone())))
            .map_err(|_| "Case save worker stopped".to_string())?;
        self.revision = revision;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<SaveCheckpoint> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Request::Checkpoint(tx))
            .map_err(|_| "Case save worker stopped".to_string())?;
        Ok(SaveCheckpoint(rx))
    }

    pub fn has_unsaved_changes(&self) -> bool {
        self.revision != self.persisted
    }

    pub fn poll(&mut self) -> Option<Result<()>> {
        match self.results.try_recv() {
            Ok((revision, result)) => {
                if result.is_ok() {
                    self.persisted = revision;
                }
                Some(result)
            }
            Err(TryRecvError::Disconnected) if !self.disconnected => {
                self.disconnected = true;
                Some(Err("Case save worker stopped".into()))
            }
            _ => None,
        }
    }
}

impl Drop for BackgroundSaves {
    fn drop(&mut self) {
        let _ = self.tx.send(Request::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
