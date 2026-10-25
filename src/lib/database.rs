//! The case database format and connection policy.
use crate::case::Result;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub const VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x56475549;
pub const DATABASE: &str = "case.sqlite";

/// Background writers wait for large imports without a fixed failure deadline.
/// Acquire before reading to avoid upgrading a stale WAL snapshot to a writer.
pub fn write_transaction<'a>(db: &'a Connection, cancel: &AtomicBool) -> Result<Transaction<'a>> {
    db.busy_timeout(Duration::from_millis(50))
        .map_err(|e| e.to_string())?;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Database write cancelled".into());
        }
        match Transaction::new_unchecked(db, TransactionBehavior::Immediate) {
            Ok(tx) => return Ok(tx),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn configure(db: Connection) -> Result<Connection> {
    db.busy_timeout(Duration::from_secs(30))
        .map_err(|e| e.to_string())?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(|e| e.to_string())?;
    Ok(db)
}

pub fn connect(directory: &Path) -> Result<Connection> {
    let db = configure(
        Connection::open_with_flags(directory.join(DATABASE), OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|e| format!("Cannot open case database: {e}"))?,
    )?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version != VERSION {
        return Err(
            "Unsupported case format. Create a new case for this pre-alpha version.".into(),
        );
    }
    let application: i64 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if application != APPLICATION_ID {
        return Err("This database is not a VolGUI case".into());
    }
    Ok(db)
}

pub fn initialize(directory: &Path) -> Result<Connection> {
    if directory.join(DATABASE).exists() {
        return connect(directory);
    }
    let db = configure(Connection::open(directory.join(DATABASE)).map_err(|e| e.to_string())?)?;
    db.execute_batch("PRAGMA journal_mode=WAL;
        BEGIN IMMEDIATE;
        CREATE TABLE case_meta(id INTEGER PRIMARY KEY CHECK(id=1),name TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE evidence(id TEXT PRIMARY KEY,path TEXT NOT NULL UNIQUE,size INTEGER NOT NULL,modified_ns TEXT,sha256 TEXT NOT NULL,added_at TEXT NOT NULL,verification_json TEXT,operating_system TEXT NOT NULL);
        CREATE TABLE analysis_runs(id TEXT PRIMARY KEY,evidence_id TEXT NOT NULL REFERENCES evidence(id),plugin TEXT NOT NULL,arguments_json TEXT NOT NULL,command_json TEXT NOT NULL,engine_version TEXT NOT NULL,created_at TEXT NOT NULL,started_at TEXT,finished_at TEXT,status TEXT NOT NULL,exit_code INTEGER,message TEXT NOT NULL,queue_hidden INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE annotations(run_id TEXT NOT NULL REFERENCES analysis_runs(id),row_index INTEGER NOT NULL,bookmarked INTEGER NOT NULL,note TEXT NOT NULL,PRIMARY KEY(run_id,row_index));
        CREATE TABLE binary_chunks(sha256 BLOB PRIMARY KEY CHECK(length(sha256)=32),size INTEGER NOT NULL,pack_offset INTEGER NOT NULL,stored_size INTEGER NOT NULL) WITHOUT ROWID;
        CREATE TABLE binary_objects(sha256 TEXT PRIMARY KEY,size INTEGER NOT NULL,manifest BLOB NOT NULL,manifest_sha256 TEXT NOT NULL);
        CREATE TABLE analysis_outputs(run_id TEXT NOT NULL REFERENCES analysis_runs(id),name TEXT NOT NULL,object_sha256 TEXT REFERENCES binary_objects(sha256),blocked_reason TEXT,PRIMARY KEY(run_id,name));
        PRAGMA user_version=2;
        PRAGMA application_id=1447515465;
        COMMIT;") .map_err(|e| format!("Cannot initialize case database: {e}"))?;
    Ok(db)
}
