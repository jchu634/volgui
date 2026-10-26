//! Immutable SHA-256 objects backed by verified, compressed 4 KiB chunks.
use crate::{case::Result, database};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const CHUNK_SIZE: usize = 4096;
const ENTRY_SIZE: usize = 48;
const MAX_MANIFEST_BYTES: u64 = 384 * 1024 * 1024;
const BLOBS: &str = "objects/blobs";
const PACK: &str = "objects/chunks.pack";

fn manifest_length(size: u64) -> Result<usize> {
    let length = size
        .div_ceil(CHUNK_SIZE as u64)
        .checked_mul(ENTRY_SIZE as u64)
        .ok_or("Object is too large")?;
    if length > MAX_MANIFEST_BYTES {
        return Err("Output exceeds the supported 32 GiB object size; capture retained".into());
    }
    Ok(length as usize)
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn archive_error(path: &Path, name: &str, error: io::Error) -> String {
    let reason = format!("Could not archive {name}: {error}");
    if matches!(error.raw_os_error(), Some(225 | 226)) {
        let _ = block(path, &reason);
    }
    reason
}

fn sql_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

#[derive(Clone)]
pub struct ObjectStore {
    root: PathBuf,
}

impl ObjectStore {
    pub fn at(directory: &Path) -> Self {
        Self {
            root: directory.to_owned(),
        }
    }

    /// Deduplicate analysis outputs; individually recovered files stay ordinary files.
    /// Bytes become durable before their SQLite references, then captures are removed.
    pub fn capture_run(&self, run: &str, cancel: &AtomicBool) -> Result<()> {
        uuid::Uuid::parse_str(run).map_err(|_| "Invalid analysis identifier")?;
        let directory = self.root.join("analyses").join(run);
        if !directory.is_dir() {
            return Ok(());
        }
        if !directory
            .canonicalize()
            .map_err(|e| e.to_string())?
            .starts_with(
                self.root
                    .canonicalize()
                    .map_err(|e| e.to_string())?
                    .join("analyses"),
            )
        {
            return Err("Analysis capture escapes the case directory".into());
        }
        fs::create_dir_all(self.root.join(BLOBS)).map_err(|e| e.to_string())?;
        // Serialize pack appends, not result imports or metadata saves. Waiting is cancellable.
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("objects/.writer.lock"))
            .map_err(|e| e.to_string())?;
        loop {
            cancelled(cancel)?;
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(25))
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        // Collect after acquiring the lock so concurrent retries cannot capture a removed file.
        let mut files = Vec::new();
        collect(&directory, &directory, &mut files)?;
        let db = database::connect(&self.root)?;
        let plugin: String = db
            .query_row("SELECT plugin FROM analysis_runs WHERE id=?1", [run], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        // DumpFiles can name an output which antivirus removed before capture.
        // Preserve that name even when directory enumeration cannot find it.
        if plugin == crate::extracted_files::DUMP_FILES
            && let Ok(json) = fs::read_to_string(directory.join("stdout.json"))
            && let Ok(table) = crate::volatility::Table::parse(&json)
        {
            for row in table.rows {
                let name = row.text("File output");
                if name.starts_with("file.")
                    && Path::new(&name).components().count() == 1
                    && matches!(
                        Path::new(&name).components().next(),
                        Some(Component::Normal(_))
                    )
                {
                    files.push(directory.join(name));
                }
            }
            files.sort();
            files.dedup();
        }
        let pack_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(PACK))
            .map_err(|e| e.to_string())?;
        let mut pending_pack = PendingPack {
            length: pack_file.metadata().map_err(|e| e.to_string())?.len(),
            file: pack_file,
            published: false,
        };
        let mut offset = pending_pack.length;
        let mut append = pending_pack.file.try_clone().map_err(|e| e.to_string())?;
        append.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        let mut pack = BufWriter::with_capacity(1024 * 1024, append);
        let mut existing_pack = ChunkFile::open(&self.root.join(PACK))?;
        // Known chunks have already been verified once during this publication.
        let mut known: HashMap<[u8; 32], Location> = HashMap::new();
        let mut chunks = Vec::new();
        let mut objects = Vec::new();
        let mut blobs = Vec::new();
        let mut blocked = Vec::new();
        let mut lookup = db
            .prepare("SELECT pack_offset,size,stored_size FROM binary_chunks WHERE sha256=?1")
            .map_err(|e| e.to_string())?;
        for path in files {
            cancelled(cancel)?;
            let name = path
                .strip_prefix(&directory)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("Output name is not UTF-8")?
                .replace('\\', "/");
            if let Some(original) = name.strip_suffix(".volgui-blocked") {
                blocked.push((
                    original.to_owned(),
                    fs::read_to_string(&path).map_err(|e| e.to_string())?,
                ));
                continue;
            }
            if plugin == crate::extracted_files::DUMP_FILES
                && !matches!(name.as_str(), "stdout.json" | "stderr.log")
            {
                match PendingBlob::copy(path.clone(), name.clone(), &self.root.join(BLOBS), cancel)
                {
                    Ok(blob) => blobs.push(blob),
                    Err(error)
                        if !cancel.load(Ordering::Relaxed)
                            && (matches!(path.try_exists(), Ok(false))
                                || error.contains("(os error 225)")
                                || error.contains("(os error 226)")) =>
                    {
                        blocked.push((
                            name,
                            format!("Recovered output unavailable, possibly quarantined: {error}"),
                        ));
                    }
                    Err(error) => return Err(error),
                }
                continue;
            }
            let mut source = BufReader::with_capacity(
                1024 * 1024,
                File::open(&path).map_err(|e| archive_error(&path, &name, e))?,
            );
            let before = source.get_ref().metadata().map_err(|e| e.to_string())?;
            let mut manifest = Vec::with_capacity(manifest_length(before.len())?);
            let mut digest = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0; CHUNK_SIZE];
            loop {
                cancelled(cancel)?;
                let mut count = 0;
                while count < buffer.len() {
                    let n = source
                        .read(&mut buffer[count..])
                        .map_err(|e| archive_error(&path, &name, e))?;
                    if n == 0 {
                        break;
                    }
                    count += n;
                }
                if count == 0 {
                    break;
                }
                if total + count as u64 > before.len() {
                    return Err("Analysis output grew while archiving; capture retained".into());
                }
                let bytes = &buffer[..count];
                digest.update(bytes);
                let sha: [u8; 32] = Sha256::digest(bytes).into();
                let location = if let Some(location) = known.get(&sha) {
                    *location
                } else {
                    let stored = lookup
                        .query_row([sha.as_slice()], |r| {
                            Ok(Location {
                                offset: sql_u64(r, 0)?,
                                size: r.get(1)?,
                                stored: r.get(2)?,
                            })
                        })
                        .optional()
                        .map_err(|e| e.to_string())?;
                    let location = if let Some(location) = stored {
                        let data = existing_pack
                            .read_chunk(location, &sha)
                            .map_err(|e| e.to_string())?;
                        if data != bytes {
                            return Err(
                                "Stored chunk does not match its incoming SHA-256 identity".into(),
                            );
                        }
                        location
                    } else {
                        let encoded = lz4_flex::block::compress(bytes);
                        let location = Location {
                            offset,
                            size: count as u32,
                            stored: encoded.len() as u32,
                        };
                        pack.write_all(&encoded).map_err(|e| e.to_string())?;
                        offset += encoded.len() as u64;
                        chunks.push((sha, location));
                        location
                    };
                    known.insert(sha, location);
                    location
                };
                manifest.extend_from_slice(&sha);
                manifest.extend_from_slice(&location.offset.to_le_bytes());
                manifest.extend_from_slice(&location.size.to_le_bytes());
                manifest.extend_from_slice(&location.stored.to_le_bytes());
                total += count as u64;
            }
            let after = source.get_ref().metadata().map_err(|e| e.to_string())?;
            if total != before.len()
                || after.len() != total
                || after.modified().ok() != before.modified().ok()
            {
                return Err("Analysis output changed while archiving; capture retained".into());
            }
            objects.push((
                path,
                name,
                format!("{:x}", digest.finalize()),
                total,
                hash(&manifest),
                lz4_flex::compress_prepend_size(&manifest),
                after.modified().ok(),
            ));
        }
        drop(lookup);
        pack.flush().map_err(|e| e.to_string())?;
        pack.get_ref().sync_all().map_err(|e| e.to_string())?;
        drop(pack);
        let tx = database::write_transaction(&db, cancel)?;
        {
            let mut insert = tx
                .prepare("INSERT INTO binary_chunks VALUES(?1,?2,?3,?4)")
                .map_err(|e| e.to_string())?;
            for (sha, location) in chunks {
                cancelled(cancel)?;
                insert
                    .execute(params![
                        sha.as_slice(),
                        location.size,
                        i64::try_from(location.offset).map_err(|_| "Chunk pack is too large")?,
                        location.stored
                    ])
                    .map_err(|e| e.to_string())?;
            }
        }
        for (_, name, sha, size, manifest_sha, manifest, _) in &objects {
            tx.execute(
                "INSERT INTO binary_objects VALUES(?1,?2,?3,?4) ON CONFLICT(sha256) DO NOTHING",
                params![sha, *size as i64, manifest, manifest_sha],
            )
            .map_err(|e| e.to_string())?;
            let identity: (u64, String, Vec<u8>) = tx
                .query_row(
                    "SELECT size,manifest_sha256,manifest FROM binary_objects WHERE sha256=?1",
                    [sha],
                    |r| Ok((sql_u64(r, 0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|e| e.to_string())?;
            if identity.0 != *size || &identity.1 != manifest_sha || &identity.2 != manifest {
                return Err("Object identity or ordered chunk manifest mismatch".into());
            }
            check_identity(&tx, run, name, sha)?;
            tx.execute("INSERT INTO analysis_outputs(run_id,name,object_sha256,size,sha256) VALUES(?1,?2,?3,?4,?3)
                ON CONFLICT(run_id,name) DO UPDATE SET object_sha256=excluded.object_sha256,size=excluded.size,sha256=excluded.sha256",
                params![run,name,sha,*size as i64]).map_err(|e|e.to_string())?;
        }
        for blob in &blobs {
            check_identity(&tx, run, &blob.name, &blob.sha256)?;
            tx.execute("INSERT INTO analysis_outputs(run_id,name,blob_id,size,sha256) VALUES(?1,?2,?3,?4,?5)
                ON CONFLICT(run_id,name) DO UPDATE SET blob_id=COALESCE(analysis_outputs.blob_id,excluded.blob_id),size=excluded.size,sha256=excluded.sha256",
                params![run,blob.name,blob.id,blob.size as i64,blob.sha256]).map_err(|e|e.to_string())?;
        }
        for (name, reason) in blocked {
            tx.execute("INSERT INTO analysis_outputs(run_id,name,blocked_reason) VALUES(?1,?2,?3) ON CONFLICT(run_id,name) DO UPDATE SET blocked_reason=excluded.blocked_reason",
                params![run,name,reason]).map_err(|e|e.to_string())?;
        }
        // A retry keeps its original ordinary file rather than orphaning it.
        let retained_blobs = blobs
            .iter()
            .map(|blob| {
                tx.query_row(
                    "SELECT blob_id FROM analysis_outputs WHERE run_id=?1 AND name=?2",
                    params![run, blob.name],
                    |r| r.get::<_, String>(0),
                )
                .map(|id| id == blob.id)
                .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>>>()?;
        cancelled(cancel)?;
        tx.commit().map_err(|e| e.to_string())?;
        pending_pack.published = true;
        for (blob, retained) in blobs.iter_mut().zip(retained_blobs) {
            blob.published = retained;
        }
        for blob in blobs {
            cleanup(&blob.original, blob.size, blob.modified)?;
        }
        for (path, _, _, size, _, _, modified) in objects {
            cleanup(&path, size, modified)?;
        }
        Ok(())
    }
}

fn cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err("Archiving analysis cancelled; capture retained".into())
    } else {
        Ok(())
    }
}

fn check_identity(db: &Connection, run: &str, name: &str, sha: &str) -> Result<()> {
    let previous: Option<String> = db
        .query_row(
            "SELECT sha256 FROM analysis_outputs WHERE run_id=?1 AND name=?2",
            params![run, name],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .flatten();
    if previous.as_ref().is_some_and(|known| known != sha) {
        return Err("An immutable analysis output changed".into());
    }
    Ok(())
}

fn cleanup(path: &Path, size: u64, modified: Option<std::time::SystemTime>) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() == size
        && metadata.modified().ok() == modified
    {
        fs::remove_file(path)
            .map_err(|e| format!("Output archived but capture cleanup failed: {e}"))
    } else {
        Err("Output archived but capture changed before cleanup".into())
    }
}

struct PendingPack {
    file: File,
    length: u64,
    published: bool,
}
impl Drop for PendingPack {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.file.set_len(self.length);
            let _ = self.file.sync_all();
        }
    }
}

struct PendingBlob {
    original: PathBuf,
    name: String,
    id: String,
    path: PathBuf,
    size: u64,
    sha256: String,
    modified: Option<std::time::SystemTime>,
    published: bool,
}

impl PendingBlob {
    fn copy(
        original: PathBuf,
        name: String,
        directory: &Path,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        let mut source = File::open(&original).map_err(|e| e.to_string())?;
        let before = source.metadata().map_err(|e| e.to_string())?;
        let id = uuid::Uuid::new_v4().to_string();
        let path = directory.join(&id);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let mut blob = Self {
            original,
            name,
            id,
            path,
            size: 0,
            sha256: String::new(),
            modified: before.modified().ok(),
            published: false,
        };
        let mut digest = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Archiving analysis cancelled; capture retained".into());
            }
            let count = source.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            blob.size += count as u64;
            if blob.size > before.len() {
                return Err("Analysis output grew while archiving; capture retained".into());
            }
            digest.update(&buffer[..count]);
            file.write_all(&buffer[..count])
                .map_err(|e| e.to_string())?;
        }
        let after = source.metadata().map_err(|e| e.to_string())?;
        if blob.size != before.len()
            || after.len() != before.len()
            || after.modified().ok() != blob.modified
        {
            return Err("Analysis output changed while archiving; capture retained".into());
        }
        file.sync_all().map_err(|e| e.to_string())?;
        blob.sha256 = format!("{:x}", digest.finalize());
        Ok(blob)
    }
}

impl Drop for PendingBlob {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn collect(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("Analysis output contains a symbolic link".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Analysis output contains a reparse point".into());
        }
    }
    if !directory
        .canonicalize()
        .map_err(|e| e.to_string())?
        .starts_with(root.canonicalize().map_err(|e| e.to_string())?)
    {
        return Err("Analysis output escapes its capture directory".into());
    }
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("Analysis output contains a symbolic link".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Analysis output contains a reparse point".into());
            }
        }
        if metadata.is_dir() {
            collect(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Decode a logical analysis path. Paths are addresses, never authoritative bytes.
fn address(path: &Path) -> Option<(PathBuf, String, String)> {
    for directory in path.ancestors() {
        if directory.file_name().is_some_and(|n| n == "analyses") {
            let root = directory.parent()?;
            if !root.join(database::DATABASE).is_file() {
                continue;
            }
            let relative = path.strip_prefix(directory).ok()?;
            if relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            {
                return None;
            }
            let mut parts = relative.components();
            let run = parts.next()?.as_os_str().to_str()?.to_owned();
            let name = parts.as_path().to_str()?.replace('\\', "/");
            return Some((root.to_owned(), run, name));
        }
    }
    None
}

pub fn stored_hash(path: &Path) -> Result<Option<String>> {
    let Some((root, run, name)) = address(path) else {
        return Ok(None);
    };
    let db = database::connect(&root)?;
    db.query_row(
        "SELECT sha256 FROM analysis_outputs WHERE run_id=?1 AND name=?2",
        params![run, name],
        |r| r.get(0),
    )
    .optional()
    .map(Option::flatten)
    .map_err(|e| e.to_string())
}

struct StoredBlob {
    path: PathBuf,
    size: u64,
    sha256: String,
}

fn stored_blob(path: &Path) -> Result<Option<StoredBlob>> {
    let Some((root, run, name)) = address(path) else {
        return Ok(None);
    };
    let db = database::connect(&root)?;
    let entry: Option<(String, i64, String)> = db
        .query_row(
            "SELECT blob_id,size,sha256 FROM analysis_outputs WHERE run_id=?1 AND name=?2 AND blob_id IS NOT NULL",
            params![run, name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    entry
        .map(|(id, size, sha256)| {
            let id = uuid::Uuid::parse_str(&id).map_err(|_| "Invalid stored blob identifier")?;
            Ok(StoredBlob {
                path: root.join(BLOBS).join(id.to_string()),
                size: u64::try_from(size).map_err(|_| "Invalid stored file size")?,
                sha256,
            })
        })
        .transpose()
}

fn open_blob(blob: &StoredBlob) -> Result<File> {
    let mut file = File::open(&blob.path).map_err(|e| format!("Stored file unavailable: {e}"))?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if before.len() != blob.size {
        return Err("Stored file size mismatch".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|e| e.to_string())?;
    if format!("{:x}", digest.finalize()) != blob.sha256
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("Stored file SHA-256 mismatch".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(file)
}

pub fn block(path: &Path, reason: &str) -> Result<bool> {
    let Some((root, run, name)) = address(path) else {
        return Ok(false);
    };
    // A handled case path must never create a sidecar marker as a fallback.
    // Busy connections and sharing violations remain retryable.
    let antivirus = !matches!(name.as_str(), "stdout.json" | "stderr.log")
        && (reason.contains("(os error 225)") || reason.contains("(os error 226)"));
    let permanent = antivirus
        || if let Some(blob) = stored_blob(path)? {
            reason.contains("Stored file SHA-256 mismatch")
                || reason.contains("Stored file size mismatch")
                || blob.path.try_exists().is_ok_and(|exists| !exists)
        } else if stored_hash(path)?.is_some() {
            [
                "manifest",
                "Stored chunk SHA-256 mismatch",
                "Corrupt stored chunk",
                "Invalid chunk bounds",
                "Complete file SHA-256 mismatch",
            ]
            .iter()
            .any(|message| reason.contains(message))
                || root.join(PACK).try_exists().is_ok_and(|exists| !exists)
        } else {
            !matches!(name.as_str(), "stdout.json" | "stderr.log")
                && path.try_exists().is_ok_and(|exists| !exists)
        };
    if !permanent {
        return Ok(true);
    }
    let db = database::connect(&root)?;
    db.execute("INSERT INTO analysis_outputs(run_id,name,blocked_reason) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM analysis_runs WHERE id=?1) ON CONFLICT(run_id,name) DO UPDATE SET blocked_reason=excluded.blocked_reason",params![run,name,reason]).map_err(|e|e.to_string())?;
    Ok(true)
}

pub fn ensure_openable(path: &Path) -> Result<()> {
    let Some((root, run, name)) = address(path) else {
        return Ok(());
    };
    let db = database::connect(&root)?;
    let reason: Option<String> = db
        .query_row(
            "SELECT blocked_reason FROM analysis_outputs WHERE run_id=?1 AND name=?2",
            params![run, name],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .flatten();
    if let Some(reason) = reason {
        return Err(format!(
            "Opening is blocked for this unavailable artifact: {reason}"
        ));
    }
    Ok(())
}

pub fn exists(path: &Path) -> bool {
    stored_hash(path).is_ok_and(|s| s.is_some()) || path.is_file()
}

pub fn list(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<_> = output_metadata(directory)?.into_keys().collect();
    files.sort();
    Ok(files)
}

pub struct OutputMetadata {
    pub sha256: Option<String>,
    pub blocked_reason: Option<String>,
}

/// One listing snapshot, avoiding database connections per rendered file.
pub fn output_metadata(directory: &Path) -> Result<HashMap<PathBuf, OutputMetadata>> {
    // Appending a placeholder lets the same decoder address the run directory.
    let Some((root, run, prefix)) = address(&directory.join(".list")) else {
        return Ok(HashMap::new());
    };
    let prefix = prefix.strip_suffix(".list").unwrap_or("");
    let db = database::connect(&root)?;
    let mut query = db
        .prepare(
            "SELECT name,sha256,blocked_reason FROM analysis_outputs WHERE run_id=?1 ORDER BY name",
        )
        .map_err(|e| e.to_string())?;
    let names = query
        .query_map([run], |r| {
            Ok((
                r.get::<_, String>(0)?,
                OutputMetadata {
                    sha256: r.get(1)?,
                    blocked_reason: r.get(2)?,
                },
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    Ok(names
        .into_iter()
        .filter_map(|(name, metadata)| {
            name.strip_prefix(prefix)
                .map(|relative| (directory.join(relative), metadata))
        })
        .collect())
}

#[derive(Clone, Copy)]
struct Location {
    offset: u64,
    size: u32,
    stored: u32,
}

struct ChunkFile {
    file: BufReader<File>,
    position: u64,
}

impl ChunkFile {
    fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            file: BufReader::with_capacity(
                1024 * 1024,
                File::open(path).map_err(|e| e.to_string())?,
            ),
            position: 0,
        })
    }

    fn read_chunk(&mut self, location: Location, expected: &[u8; 32]) -> io::Result<Vec<u8>> {
        let Location {
            offset,
            size,
            stored,
        } = location;
        if size == 0
            || size as usize > CHUNK_SIZE
            || stored == 0
            || stored as usize > CHUNK_SIZE + 64
        {
            return Err(error("Invalid chunk bounds"));
        }
        let delta = i64::try_from(i128::from(offset) - i128::from(self.position))
            .map_err(|_| error("Invalid chunk bounds"))?;
        self.file.seek_relative(delta)?;
        self.position = offset;
        let mut encoded = vec![0; stored as usize];
        if let Err(error) = self.file.read_exact(&mut encoded) {
            self.position = self.file.stream_position()?;
            return Err(error);
        }
        self.position += u64::from(stored);
        let bytes = lz4_flex::block::decompress(&encoded, size as usize)
            .map_err(|e| error(format!("Corrupt stored chunk: {e}")))?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if &actual != expected || bytes.len() != size as usize {
            return Err(error("Stored chunk SHA-256 mismatch"));
        }
        Ok(bytes)
    }
}

pub struct ObjectReader {
    pack: ChunkFile,
    // Each authenticated entry includes the digest and location. Reading bytes needs no SQL.
    manifest: Vec<u8>,
    size: u64,
    position: u64,
    cached: Option<(usize, Vec<u8>)>,
    whole_hash: Option<Sha256>,
    expected: String,
}

impl ObjectReader {
    fn open(root: &Path, sha: &str) -> Result<Self> {
        let db = database::connect(root)?;
        let (size, manifest, manifest_sha): (u64, Vec<u8>, String) = db
            .query_row(
                "SELECT size,manifest,manifest_sha256 FROM binary_objects WHERE sha256=?1",
                [sha],
                |r| Ok((sql_u64(r, 0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        let expected_length = manifest_length(size)?;
        let announced = manifest
            .get(..4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as usize)
            .ok_or("Truncated object manifest")?;
        if announced != expected_length {
            return Err("Invalid object manifest size".into());
        }
        let manifest = lz4_flex::decompress_size_prepended(&manifest)
            .map_err(|e| format!("Invalid object manifest: {e}"))?;
        if manifest.len() != expected_length || hash(&manifest) != manifest_sha {
            return Err("Object chunk manifest SHA-256 mismatch".into());
        }
        Ok(Self {
            pack: ChunkFile::open(&root.join(PACK))?,
            manifest,
            size,
            position: 0,
            cached: None,
            whole_hash: Some(Sha256::new()),
            expected: sha.into(),
        })
    }
}

impl Read for ObjectReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.position >= self.size {
            if let Some(digest) = &self.whole_hash
                && format!("{:x}", digest.clone().finalize()) != self.expected
            {
                return Err(error("Complete file SHA-256 mismatch"));
            }
            return Ok(0);
        }
        let mut written = 0;
        while written < buffer.len() && self.position < self.size {
            let index = (self.position / CHUNK_SIZE as u64) as usize;
            if self.cached.as_ref().is_none_or(|(i, _)| *i != index) {
                let entry = &self.manifest[index * ENTRY_SIZE..(index + 1) * ENTRY_SIZE];
                let sha: [u8; 32] = entry[..32].try_into().unwrap();
                let location = Location {
                    offset: u64::from_le_bytes(entry[32..40].try_into().unwrap()),
                    size: u32::from_le_bytes(entry[40..44].try_into().unwrap()),
                    stored: u32::from_le_bytes(entry[44..48].try_into().unwrap()),
                };
                let expected =
                    (self.size - index as u64 * CHUNK_SIZE as u64).min(CHUNK_SIZE as u64);
                if u64::from(location.size) != expected {
                    return Err(error("Chunk length does not match object extent"));
                }
                self.cached = Some((index, self.pack.read_chunk(location, &sha)?));
            }
            let offset = (self.position % CHUNK_SIZE as u64) as usize;
            let bytes = &self.cached.as_ref().unwrap().1;
            let count = (buffer.len() - written).min(bytes.len() - offset);
            buffer[written..written + count].copy_from_slice(&bytes[offset..offset + count]);
            if let Some(digest) = &mut self.whole_hash {
                digest.update(&bytes[offset..offset + count]);
            }
            self.position += count as u64;
            written += count;
        }
        // Verify at the final byte, including consumers that use read_exact rather than EOF.
        if self.position == self.size
            && let Some(digest) = &self.whole_hash
            && format!("{:x}", digest.clone().finalize()) != self.expected
        {
            return Err(error("Complete file SHA-256 mismatch"));
        }
        Ok(written)
    }
}

impl Seek for ObjectReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(n) => i128::from(self.size) + i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
        };
        let position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid seek position"))?;
        if position != self.position {
            self.whole_hash = if position == 0 {
                Some(Sha256::new())
            } else {
                None
            };
        }
        self.position = position;
        Ok(position)
    }
}

pub enum ArtifactReader {
    File(File),
    Object(Box<ObjectReader>),
}

pub struct ArtifactMetadata(u64);
impl ArtifactMetadata {
    pub fn len(&self) -> u64 {
        self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}
impl ArtifactReader {
    pub fn metadata(&self) -> io::Result<ArtifactMetadata> {
        Ok(ArtifactMetadata(match self {
            Self::File(f) => f.metadata()?.len(),
            Self::Object(o) => o.size,
        }))
    }
}
impl Read for ArtifactReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(buffer),
            Self::Object(o) => o.read(buffer),
        }
    }
}
impl Seek for ArtifactReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(position),
            Self::Object(o) => o.seek(position),
        }
    }
}

pub fn open(path: &Path) -> Result<ArtifactReader> {
    ensure_openable(path)?;
    if let Some(blob) = stored_blob(path)? {
        return open_blob(&blob).map(ArtifactReader::File);
    }
    if let Some((root, _, _)) = address(path)
        && let Some(sha) = stored_hash(path)?
    {
        return ObjectReader::open(&root, &sha).map(|o| ArtifactReader::Object(Box::new(o)));
    }
    File::open(path)
        .map(ArtifactReader::File)
        .map_err(|e| e.to_string())
}

/// A disposable, verified copy owned by its consumer, outside the case.
pub fn materialize(path: &Path) -> Result<tempfile::NamedTempFile> {
    let mut source = open(path)?;
    let mut file = tempfile::Builder::new()
        .prefix("volgui-view-")
        .tempfile()
        .map_err(|e| e.to_string())?;
    io::copy(&mut source, &mut file).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    #[test]
    fn writer_and_reader_share_an_overflow_safe_manifest_bound() {
        let maximum = 32 * 1024 * 1024 * 1024;
        assert_eq!(super::manifest_length(maximum).unwrap(), 384 * 1024 * 1024);
        assert!(super::manifest_length(maximum + 1).is_err());
        assert!(super::manifest_length(u64::MAX).is_err());
    }
}
