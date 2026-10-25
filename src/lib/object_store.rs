//! Immutable SHA-256 objects backed by verified, compressed 4 KiB chunks.
use crate::{case::Result, database};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const CHUNK_SIZE: usize = 4096;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
const PACK: &str = "objects/chunks.pack";

fn manifest_length(size: u64) -> Result<usize> {
    let length = size
        .div_ceil(CHUNK_SIZE as u64)
        .checked_mul(32)
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

    /// Catalog and durably store outputs before removing any captured bytes.
    /// Uncommitted pack tails are unreachable and safe after interruption.
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
        let mut files = Vec::new();
        collect(&directory, &directory, &mut files)?;
        if files.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(self.root.join("objects")).map_err(|e| e.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("objects/.writer.lock"))
            .map_err(|e| e.to_string())?;
        lock.lock().map_err(|e| e.to_string())?;
        let db = database::connect(&self.root)?;
        let mut pack = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(self.root.join(PACK))
            .map_err(|e| e.to_string())?;
        let mut chunks: HashMap<[u8; 32], (u64, usize, usize)> = HashMap::new();
        let mut objects = Vec::new();
        let mut blocked = Vec::new();
        let mut lookup = db
            .prepare("SELECT pack_offset,size,stored_size FROM binary_chunks WHERE sha256=?1")
            .map_err(|e| e.to_string())?;
        for path in &files {
            if cancel.load(Ordering::Relaxed) {
                return Err("Archiving analysis cancelled; capture retained".into());
            }
            let name = path
                .strip_prefix(&directory)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("Output name is not UTF-8")?
                .replace('\\', "/");
            if let Some(original) = name.strip_suffix(".volgui-blocked") {
                blocked.push((
                    original.to_owned(),
                    fs::read_to_string(path).map_err(|e| e.to_string())?,
                ));
                continue;
            }
            let mut source =
                File::open(path).map_err(|e| format!("Cannot archive {}: {e}", path.display()))?;
            let before = source.metadata().map_err(|e| e.to_string())?;
            manifest_length(before.len())?;
            let mut digest = Sha256::new();
            let mut manifest = Vec::new();
            let mut total = 0u64;
            let mut buffer = [0; CHUNK_SIZE];
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Archiving analysis cancelled; capture retained".into());
                }
                let mut count = 0;
                while count < buffer.len() {
                    let n = source
                        .read(&mut buffer[count..])
                        .map_err(|e| e.to_string())?;
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
                let chunk: [u8; 32] = Sha256::digest(bytes).into();
                manifest.extend_from_slice(&chunk);
                let location = if let Some(location) = chunks.get(&chunk) {
                    Some(*location)
                } else {
                    lookup
                        .query_row([chunk.as_slice()], |r| {
                            Ok((
                                r.get::<_, i64>(0)? as u64,
                                r.get::<_, i64>(1)? as usize,
                                r.get::<_, i64>(2)? as usize,
                            ))
                        })
                        .optional()
                        .map_err(|e| e.to_string())?
                };
                if let Some((offset, size, stored)) = location {
                    let existing = read_chunk(&mut pack, offset, size, stored, &chunk)
                        .map_err(|e| e.to_string())?;
                    if existing != bytes {
                        return Err(
                            "Stored chunk does not match its incoming SHA-256 identity".into()
                        );
                    }
                } else {
                    let compressed = lz4_flex::block::compress(bytes);
                    let offset = pack.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
                    pack.write_all(&compressed).map_err(|e| e.to_string())?;
                    chunks.insert(chunk, (offset, count, compressed.len()));
                }
                total += count as u64;
            }
            let after = source.metadata().map_err(|e| e.to_string())?;
            if before.len() != total
                || after.len() != total
                || before.modified().ok() != after.modified().ok()
            {
                return Err("Analysis output changed while archiving; capture retained".into());
            }
            objects.push((
                path.clone(),
                name,
                format!("{:x}", digest.finalize()),
                total,
                hash(&manifest),
                lz4_flex::compress_prepend_size(&manifest),
                after.modified().ok(),
            ));
        }
        drop(lookup);
        pack.sync_all().map_err(|e| e.to_string())?;
        if cancel.load(Ordering::Relaxed) {
            return Err("Archiving analysis cancelled; capture retained".into());
        }
        let tx = database::write_transaction(&db, cancel)?;
        {
            let mut insert = tx
                .prepare("INSERT INTO binary_chunks VALUES(?1,?2,?3,?4)")
                .map_err(|e| e.to_string())?;
            for (chunk, (offset, size, stored)) in &chunks {
                insert
                    .execute(params![
                        chunk.as_slice(),
                        *size as i64,
                        *offset as i64,
                        *stored as i64
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
            let (known_size, known_manifest): (i64, String) = tx
                .query_row(
                    "SELECT size,manifest_sha256 FROM binary_objects WHERE sha256=?1",
                    [sha],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| e.to_string())?;
            if known_size as u64 != *size || known_manifest != *manifest_sha {
                return Err("Object identity or ordered chunk manifest mismatch".into());
            }
            let previous: Option<String> = tx
                .query_row(
                    "SELECT object_sha256 FROM analysis_outputs WHERE run_id=?1 AND name=?2",
                    params![run, name],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .flatten();
            if previous.as_ref().is_some_and(|p| p != sha) {
                return Err("An immutable analysis output changed".into());
            }
            tx.execute("INSERT INTO analysis_outputs(run_id,name,object_sha256) VALUES(?1,?2,?3) ON CONFLICT(run_id,name) DO UPDATE SET object_sha256=excluded.object_sha256",params![run,name,sha]).map_err(|e|e.to_string())?;
        }
        for (name, reason) in blocked {
            tx.execute("INSERT INTO analysis_outputs(run_id,name,blocked_reason) VALUES(?1,?2,?3) ON CONFLICT(run_id,name) DO UPDATE SET blocked_reason=excluded.blocked_reason",params![run,name,reason]).map_err(|e|e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        // References are durable. Delete only the exact regular files inspected.
        for (path, _, _, size, _, _, modified) in objects {
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == size
                && metadata.modified().ok() == modified
            {
                fs::remove_file(&path)
                    .map_err(|e| format!("Output archived but capture cleanup failed: {e}"))?;
            } else {
                return Err("Output archived but capture changed before cleanup".into());
            }
        }
        Ok(())
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
        "SELECT object_sha256 FROM analysis_outputs WHERE run_id=?1 AND name=?2",
        params![run, name],
        |r| r.get(0),
    )
    .optional()
    .map(Option::flatten)
    .map_err(|e| e.to_string())
}

pub fn block(path: &Path, reason: &str) -> Result<bool> {
    let Some((root, run, name)) = address(path) else {
        return Ok(false);
    };
    // A handled case path must never create a sidecar marker as a fallback.
    // Busy connections and sharing violations remain retryable.
    let permanent = if stored_hash(path)?.is_some() {
        [
            "Object chunk manifest SHA-256 mismatch",
            "Invalid object manifest",
            "Truncated object manifest",
            "Stored chunk SHA-256 mismatch",
            "Complete file SHA-256 mismatch",
            "Corrupt stored chunk",
            "Invalid chunk bounds",
        ]
        .iter()
        .any(|message| reason.contains(message))
            || !root.join(PACK).try_exists().unwrap_or(true)
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
        .prepare("SELECT name,object_sha256,blocked_reason FROM analysis_outputs WHERE run_id=?1 ORDER BY name")
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

fn read_chunk(
    pack: &mut File,
    offset: u64,
    size: usize,
    stored: usize,
    expected: &[u8; 32],
) -> io::Result<Vec<u8>> {
    if size == 0 || size > CHUNK_SIZE || stored == 0 || stored > CHUNK_SIZE + 64 {
        return Err(error("Invalid chunk bounds"));
    }
    pack.seek(SeekFrom::Start(offset))?;
    let mut encoded = vec![0; stored];
    pack.read_exact(&mut encoded)?;
    let data = lz4_flex::block::decompress(&encoded, size)
        .map_err(|e| error(format!("Corrupt stored chunk: {e}")))?;
    let actual: [u8; 32] = Sha256::digest(&data).into();
    if &actual != expected || data.len() != size {
        return Err(error("Stored chunk SHA-256 mismatch"));
    }
    Ok(data)
}

pub struct ObjectReader {
    db: Connection,
    pack: File,
    chunks: Vec<[u8; 32]>,
    size: u64,
    position: u64,
    cached: Option<(usize, Vec<u8>)>,
    whole_hash: Option<Sha256>,
    expected: String,
}

impl ObjectReader {
    fn open(root: &Path, sha: &str) -> Result<Self> {
        let db = database::connect(root)?;
        let (size, manifest, manifest_sha): (i64, Vec<u8>, String) = db
            .query_row(
                "SELECT size,manifest,manifest_sha256 FROM binary_objects WHERE sha256=?1",
                [sha],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        let size = u64::try_from(size).map_err(|_| "Invalid object size")?;
        let expected_length = manifest_length(size)? as u64;
        let announced = manifest
            .get(..4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as u64)
            .ok_or("Truncated object manifest")?;
        if announced != expected_length {
            return Err("Invalid object manifest size".into());
        }
        let manifest = lz4_flex::decompress_size_prepended(&manifest).map_err(|e| e.to_string())?;
        if hash(&manifest) != manifest_sha {
            return Err("Object chunk manifest SHA-256 mismatch".into());
        }
        let chunks = manifest
            .chunks_exact(32)
            .map(|s| s.try_into().unwrap())
            .collect();
        let pack = File::open(root.join(PACK)).map_err(|e| e.to_string())?;
        Ok(Self {
            db,
            pack,
            chunks,
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
        let index = (self.position / CHUNK_SIZE as u64) as usize;
        if self.cached.as_ref().is_none_or(|(i, _)| *i != index) {
            let sha = &self.chunks[index];
            let (offset, size, stored): (u64, usize, usize) = self
                .db
                .query_row(
                    "SELECT pack_offset,size,stored_size FROM binary_chunks WHERE sha256=?1",
                    [sha.as_slice()],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)? as u64,
                            r.get::<_, i64>(1)? as usize,
                            r.get::<_, i64>(2)? as usize,
                        ))
                    },
                )
                .map_err(|e| error(e.to_string()))?;
            let expected =
                (self.size - index as u64 * CHUNK_SIZE as u64).min(CHUNK_SIZE as u64) as usize;
            if size != expected {
                return Err(error("Chunk length does not match object extent"));
            }
            self.cached = Some((
                index,
                read_chunk(&mut self.pack, offset, size, stored, sha)?,
            ));
        }
        let offset = (self.position % CHUNK_SIZE as u64) as usize;
        let bytes = &self.cached.as_ref().unwrap().1;
        let count = buffer.len().min(bytes.len() - offset);
        buffer[..count].copy_from_slice(&bytes[offset..offset + count]);
        if let Some(digest) = &mut self.whole_hash {
            digest.update(&buffer[..count]);
        }
        self.position += count as u64;
        Ok(count)
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
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(b),
            Self::Object(o) => o.read(b),
        }
    }
}
impl Seek for ArtifactReader {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(p),
            Self::Object(o) => o.seek(p),
        }
    }
}

pub fn open(path: &Path) -> Result<ArtifactReader> {
    ensure_openable(path)?;
    if let Some((root, _, _)) = address(path)
        && let Some(sha) = stored_hash(path)?
    {
        return ObjectReader::open(&root, &sha)
            .map(|reader| ArtifactReader::Object(Box::new(reader)));
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
        assert_eq!(super::manifest_length(maximum).unwrap(), 256 * 1024 * 1024);
        assert!(super::manifest_length(maximum + 1).is_err());
        assert!(super::manifest_length(u64::MAX).is_err());
    }
}
