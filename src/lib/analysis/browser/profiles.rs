//! Share immutable profile parsing between Browser and Download jobs.
use super::{MAX_ROWS, SESSION_LIMIT, chromium_session, firefox_session, history, read_session};
use crate::volatility::Record;
use std::{
    collections::{BTreeMap, VecDeque},
    io::Read,
    path::Path,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

const VERSION: &str = "browser-profiles-v1";
const CACHE_BYTES: usize = 32 * 1024 * 1024;
const CACHE_ENTRIES: usize = 4096;

#[derive(Clone)]
pub(super) struct Profile {
    pub rows: Vec<Record>,
    pub error: Option<String>,
}

#[derive(Default)]
struct Cache {
    entries: BTreeMap<(String, bool), (Profile, usize)>,
    order: VecDeque<(String, bool)>,
    bytes: usize,
}

pub(super) fn read(
    path: &Path,
    file: &mut impl Read,
    hash: Option<&str>,
    fallback: bool,
    cancel: &AtomicBool,
) -> Result<(Profile, bool), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("Browser analysis cancelled".into());
    }
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);
    let key = hash.map(|hash| (format!("{VERSION}:{hash}"), fallback));
    // Keep the same availability and first-chunk integrity checks on cache hits.
    let mut head = [0; 16];
    let size = file.read(&mut head).map_err(|e| e.to_string())?;
    if let Some(key) = &key
        && let Some((profile, _)) = cache.lock().map_err(|e| e.to_string())?.entries.get(key)
    {
        return Ok((profile.clone(), true));
    }
    let mut rows = Vec::new();
    let result = if head[..size].starts_with(b"SQLite format 3\0") {
        history(path, &mut rows, cancel)
    } else if head[..size].starts_with(b"SNSS") {
        read_session(path).and_then(|data| chromium_session(&data, &mut rows))
    } else if head[..size].starts_with(b"mozLz40\0") {
        read_session(path).and_then(|data| {
            let length = data
                .get(8..12)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_le_bytes)
                .ok_or("Truncated Mozilla LZ4 header")?;
            if u64::from(length) > SESSION_LIMIT {
                return Err("Mozilla session exceeds 32 MiB decompression limit".into());
            }
            let json = lz4_flex::block::decompress_size_prepended(&data[8..])
                .map_err(|e| e.to_string())?;
            firefox_session(&json, &mut rows)
        })
    } else if fallback {
        read_session(path).and_then(|data| firefox_session(&data, &mut rows))
    } else {
        Ok(())
    };
    if cancel.load(Ordering::Relaxed) {
        return Err("Browser analysis cancelled".into());
    }
    let profile = Profile {
        rows,
        error: result.err(),
    };
    // Failed or bounded parses must be retried after inputs or scope change.
    if let Some(key) = key
        && profile.error.is_none()
        && profile.rows.len() < MAX_ROWS
    {
        let size = profile
            .rows
            .iter()
            .map(|r| serde_json::to_vec(&r.fields).map_or(CACHE_BYTES, |v| v.len()))
            .sum::<usize>()
            + key.0.len();
        if size <= CACHE_BYTES {
            let mut cache = cache.lock().map_err(|e| e.to_string())?;
            if !cache.entries.contains_key(&key) {
                while cache.bytes + size > CACHE_BYTES || cache.entries.len() >= CACHE_ENTRIES {
                    let Some(oldest) = cache.order.pop_front() else {
                        break;
                    };
                    if let Some((_, bytes)) = cache.entries.remove(&oldest) {
                        cache.bytes -= bytes;
                    }
                }
                cache.bytes += size;
                cache.order.push_back(key.clone());
                cache.entries.insert(key, (profile.clone(), size));
            }
        }
    }
    Ok((profile, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn immutable_cache_preserves_unknown_source_fallback_and_checks_availability() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovered.dat");
        let data = br#"{"windows":[{"tabs":[{"entries":[{"url":"https://example.test/cache-fixture","title":"Cached tab"}],"index":1}]}]}"#;
        std::fs::write(&path, data).unwrap();
        let hash = format!("{:x}", Sha256::digest(data));
        let parse = |fallback| {
            let mut file = std::fs::File::open(&path).unwrap();
            read(
                &path,
                &mut file,
                Some(&hash),
                fallback,
                &AtomicBool::new(false),
            )
            .unwrap()
        };
        let (unknown, _) = parse(false);
        assert!(unknown.rows.is_empty());
        let (first, cached) = parse(true);
        assert!(!cached);
        assert_eq!(first.rows.len(), 1);
        assert!(
            !first.rows[0].fields.contains_key("Source run"),
            "Provenance is assigned per job"
        );
        let (again, cached) = parse(true);
        assert!(cached);
        assert_eq!(first.rows[0].fields, again.rows[0].fields);
        let mut unavailable = std::io::empty();
        // A cached row never suppresses an actual read error.
        struct Unavailable;
        impl Read for Unavailable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::NotFound.into())
            }
        }
        assert!(
            read(
                &path,
                &mut Unavailable,
                Some(&hash),
                true,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert!(
            read(
                &path,
                &mut unavailable,
                Some(&hash),
                true,
                &AtomicBool::new(true)
            )
            .is_err()
        );
    }
}
