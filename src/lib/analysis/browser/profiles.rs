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

const VERSION: &str = "browser-profiles-v2";
const CACHE_BYTES: usize = 32 * 1024 * 1024;
const CACHE_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Source {
    Unknown,
    History,
    Session,
}

impl Source {
    pub(super) fn named(path: &str) -> Option<Self> {
        let path = path.replace('/', "\\").to_lowercase();
        let name = path.rsplit('\\').next().unwrap_or("");
        match name {
            "history" | "places.sqlite" => Some(Self::History),
            "current session"
            | "last session"
            | "sessionstore.json"
            | "sessionstore.js"
            | "recovery.jsonlz4"
            | "previous.jsonlz4"
            | "sessionstore.jsonlz4"
            | "recovery.baklz4" => Some(Self::Session),
            _ if name.starts_with("session_") => Some(Self::Session),
            _ => None,
        }
    }

    pub(super) fn recovered(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        // DumpFiles embeds the original basename between its section type and suffix.
        // A known non-browser basename can be excluded before opening its bytes.
        let fields: Vec<_> = name.splitn(5, '.').collect();
        if let ["file", _, _, section, output] = fields.as_slice()
            && matches!(
                *section,
                "DataSectionObject" | "SharedCacheMap" | "ImageSectionObject"
            )
            && let Some((original, _)) = output.rsplit_once('.')
        {
            return Self::named(original);
        }
        Some(Self::named(name).unwrap_or(Self::Unknown))
    }
}

#[derive(Clone)]
pub(super) struct Profile {
    pub rows: Vec<Record>,
    pub error: Option<String>,
}

#[derive(Default)]
struct Cache {
    entries: BTreeMap<(String, Source, bool), (Profile, usize)>,
    order: VecDeque<(String, Source, bool)>,
    bytes: usize,
}

pub(super) fn read(
    path: &Path,
    file: &mut impl Read,
    hash: Option<&str>,
    source: Source,
    cancel: &AtomicBool,
) -> Result<(Profile, bool), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("Browser analysis cancelled".into());
    }
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);
    let json = path.extension().is_some_and(|s| s == "json" || s == "js");
    let key = hash.map(|hash| (format!("{VERSION}:{hash}"), source, json));
    // Keep the same availability and first-chunk integrity checks on cache hits.
    let mut head = [0; 16];
    let size = file.read(&mut head).map_err(|e| e.to_string())?;
    if let Some(key) = &key
        && let Some((profile, _)) = cache.lock().map_err(|e| e.to_string())?.entries.get(key)
    {
        return Ok((profile.clone(), true));
    }
    let mut rows = Vec::new();
    let sqlite = head[..size].starts_with(b"SQLite format 3\0");
    let chromium = head[..size].starts_with(b"SNSS");
    let mozilla = head[..size].starts_with(b"mozLz40\0");
    let result = if source == Source::History && !sqlite {
        Err("Expected a SQLite browser history database; recovered header is missing or unsupported".into())
    } else if sqlite {
        history(path, &mut rows, cancel, source == Source::History)
    } else if chromium {
        read_session(path).and_then(|data| chromium_session(&data, &mut rows))
    } else if mozilla {
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
    } else if source == Source::Session || json {
        read_session(path).and_then(|data| firefox_session(&data, &mut rows))
    } else {
        Ok(())
    };
    if cancel.load(Ordering::Relaxed) {
        return Err("Browser analysis cancelled".into());
    }
    let error = result
        .err()
        .filter(|_| source != Source::Unknown || sqlite || chromium || mozilla || !rows.is_empty());
    let profile = Profile { rows, error };
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
    fn dump_names_select_browser_profiles_before_opening_outputs() {
        for (name, expected) in [
            (
                "file.0x1000.0x2000.SharedCacheMap.History.vacb",
                Some(Source::History),
            ),
            (
                "file.0x1000.0x2000.DataSectionObject.places.sqlite.dat",
                Some(Source::History),
            ),
            (
                "file.0x1000.0x2000.DataSectionObject.Session_123.dat",
                Some(Source::Session),
            ),
            ("file.0x1000.0x2000.SharedCacheMap.Cookies.vacb", None),
            ("file.0x1000.0x2000.DataSectionObject.Windows.db.dat", None),
            (
                "file.0x1000.0x2000.ImageSectionObject.rdpclip.exe.img",
                None,
            ),
            ("unidentified.dat", Some(Source::Unknown)),
        ] {
            assert_eq!(Source::recovered(Path::new(name)), expected, "{name}");
        }
    }

    #[test]
    fn unidentified_sqlite_is_skipped_but_expected_history_warns_with_same_hash() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovered.dat");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE cookies (name TEXT)")
            .unwrap();
        drop(db);
        let hash = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
        for source in [Source::Unknown, Source::History] {
            let (profile, _) = read(
                &path,
                &mut std::fs::File::open(&path).unwrap(),
                Some(&hash),
                source,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert!(profile.rows.is_empty());
            assert_eq!(profile.error.is_some(), source == Source::History);
        }
    }

    #[test]
    fn history_without_a_sqlite_header_never_falls_back_to_session_json() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("History.dat");
        std::fs::write(&path, b"missing recovered header").unwrap();
        let (profile, _) = read(
            &path,
            &mut std::fs::File::open(&path).unwrap(),
            None,
            Source::History,
            &AtomicBool::new(false),
        )
        .unwrap();
        let error = profile.error.unwrap();
        assert!(error.contains("Expected a SQLite browser history database"));
        assert!(!error.contains("JSON"));
    }

    #[test]
    fn unrelated_json_is_not_a_session_coverage_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");
        std::fs::write(&path, br#"{"setting":true}"#).unwrap();
        let (profile, _) = read(
            &path,
            &mut std::fs::File::open(&path).unwrap(),
            None,
            Source::Unknown,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(profile.rows.is_empty());
        assert!(profile.error.is_none());
    }

    #[test]
    fn immutable_cache_preserves_unknown_source_fallback_and_checks_availability() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovered.dat");
        let data = br#"{"windows":[{"tabs":[{"entries":[{"url":"https://example.test/cache-fixture","title":"Cached tab"}],"index":1}]}]}"#;
        std::fs::write(&path, data).unwrap();
        let hash = format!("{:x}", Sha256::digest(data));
        let parse = |source| {
            let mut file = std::fs::File::open(&path).unwrap();
            read(
                &path,
                &mut file,
                Some(&hash),
                source,
                &AtomicBool::new(false),
            )
            .unwrap()
        };
        let (unknown, _) = parse(Source::Unknown);
        assert!(unknown.rows.is_empty());
        let json_path = temp.path().join("unidentified.json");
        std::fs::write(&json_path, data).unwrap();
        let (json, _) = read(
            &json_path,
            &mut std::fs::File::open(&json_path).unwrap(),
            Some(&hash),
            Source::Unknown,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            json.rows.len(),
            1,
            "A non-JSON cache entry must not hide JSON sessions"
        );
        let (first, cached) = parse(Source::Session);
        assert!(!cached);
        assert_eq!(first.rows.len(), 1);
        assert!(
            !first.rows[0].fields.contains_key("Source run"),
            "Provenance is assigned per job"
        );
        let (again, cached) = parse(Source::Session);
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
                Source::Session,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert!(
            read(
                &path,
                &mut unavailable,
                Some(&hash),
                Source::Session,
                &AtomicBool::new(true)
            )
            .is_err()
        );
    }
}
