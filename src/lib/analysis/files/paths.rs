//! Executable path references complement FileScan when no FILE_OBJECT survives.
use crate::volatility::Record;
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const CHUNK: usize = 1024 * 1024;
const WINDOW: usize = 8192;
pub(super) const MAX_PATHS: usize = 10_000;
pub(super) const MAX_PARTIAL_PATHS: usize = 1_000;

fn partial_path(text: &str) -> Option<&str> {
    let name = text.trim_start();
    if name.len() > 2048
        || name.contains([':', '"', '<', '>', '|', '?', '*', '\u{fffd}'])
        || name.chars().any(char::is_control)
    {
        return None;
    }
    let parts: Vec<_> = name.split('\\').collect();
    if !(2..=20).contains(&parts.len()) {
        return None;
    }
    let components = if name.starts_with("\\\\") {
        let host = *parts.get(2)?;
        if host.len() < 2
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
            || parts.len() < 5
        {
            return None;
        }
        &parts[2..]
    } else if name.starts_with('\\') {
        if parts.len() < 3 {
            return None;
        }
        &parts[1..]
    } else {
        &parts[..]
    };
    if components
        .iter()
        .any(|p| p.is_empty() || p.len() > 255 || p.trim() != *p)
    {
        return None;
    }
    let file = components.last()?;
    let stem = file.get(..file.len().checked_sub(4)?)?;
    let letters = stem
        .chars()
        .filter(char::is_ascii_alphabetic)
        .collect::<std::collections::BTreeSet<_>>();
    if !file.to_ascii_lowercase().ends_with(".exe")
        || letters.len() < 3
        || stem
            .chars()
            .any(|c| !(c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.')))
    {
        return None;
    }
    Some(name)
}

pub(super) fn scan(
    path: &Path,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<Vec<Record>, String> {
    // Literal searches skip most evidence bytes without decoding every string.
    let extensions: Vec<_> = [
        (b".e".as_slice(), 0),
        (b".E".as_slice(), 0),
        (b".\0e\0".as_slice(), 1),
        (b".\0E\0".as_slice(), 1),
        (b"\0.\0e".as_slice(), 2),
        (b"\0.\0E".as_slice(), 2),
    ]
    .into_iter()
    .map(|(needle, encoding)| (memchr::memmem::Finder::new(needle), encoding))
    .collect();
    let paths = regex::Regex::new(r#"(?i)[a-z]:\\[^\x00-\x1f<>:"|?*\u{fffd}]{1,2048}\.exe$"#)
        .map_err(|e| e.to_string())?;
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut chunk = vec![0; CHUNK];
    let mut buffer = Vec::new();
    let mut base = 0u64;
    let mut processed = 0u64;
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    let mut partial_rows = Vec::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("File path search cancelled".into());
        }
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        buffer.extend_from_slice(&chunk[..n]);
        let end = if n == 0 {
            buffer.len()
        } else {
            buffer.len().saturating_sub(2)
        };
        let mut hits = Vec::new();
        for (finder, encoding) in &extensions {
            let suffix: &[u8] = match encoding {
                0 => b".exe",
                1 => b".\0e\0x\0e\0",
                _ => b"\0.\0e\0x\0e",
            };
            for start in finder.find_iter(&buffer) {
                if buffer
                    .get(start..start + suffix.len())
                    .is_some_and(|b| b.eq_ignore_ascii_case(suffix))
                {
                    hits.push((start + suffix.len(), *encoding));
                }
            }
        }
        hits.sort_unstable();
        for (hit_end, encoding) in hits {
            let absolute_end = base + hit_end as u64;
            if absolute_end <= processed || hit_end > end {
                continue;
            }
            let step = if encoding == 0 { 1 } else { 2 };
            let next = &buffer[hit_end..];
            let next = if step == 1 {
                next.first().copied().map(u16::from)
            } else {
                next.get(..2).map(|b| {
                    if encoding == 1 {
                        u16::from_le_bytes([b[0], b[1]])
                    } else {
                        u16::from_be_bytes([b[0], b[1]])
                    }
                })
            };
            if next
                .and_then(|c| char::from_u32(c.into()))
                .is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '.'))
            {
                continue;
            }
            let limit = hit_end.saturating_sub(WINDOW);
            let mut start = hit_end;
            while start >= limit + step {
                let at = start - step;
                let unit = match encoding {
                    0 => u16::from(buffer[at]),
                    1 => u16::from_le_bytes([buffer[at], buffer[at + 1]]),
                    _ => u16::from_be_bytes([buffer[at], buffer[at + 1]]),
                };
                if unit < 32 || matches!(unit, 34 | 42 | 60 | 62 | 63 | 124) {
                    break;
                }
                start = at;
            }
            let bytes = &buffer[start..hit_end];
            let text = if encoding == 0 {
                String::from_utf8_lossy(bytes).into_owned()
            } else {
                let units: Vec<_> = bytes
                    .chunks_exact(2)
                    .map(|b| {
                        if encoding == 1 {
                            u16::from_le_bytes([b[0], b[1]])
                        } else {
                            u16::from_be_bytes([b[0], b[1]])
                        }
                    })
                    .collect();
                String::from_utf16_lossy(&units)
            };
            let strict = paths.find(&text);
            let Some(name) = strict
                .as_ref()
                .map(|found| found.as_str())
                .or_else(|| partial_path(&text))
            else {
                continue;
            };
            let is_partial = strict.is_none();
            if is_partial && partial_rows.len() >= MAX_PARTIAL_PATHS {
                continue;
            }
            if !seen.insert(name.to_lowercase()) {
                continue;
            }
            let length = if encoding == 0 {
                name.len()
            } else {
                name.encode_utf16().count() * 2
            };
            let mut row = super::super::record(serde_json::json!({
                "Name": name,
                "Kind": "Referenced executable path",
                "Recovery status": "Path reference only",
                "Evidence offset": absolute_end - length as u64,
                "Encoding": (["UTF-8", "UTF-16LE", "UTF-16BE"][encoding]),
                "Source file": path.display().to_string()
            }));
            if is_partial {
                super::super::partial::mark(
                    &mut row,
                    "Executable path reference",
                    &["No drive-qualified absolute Windows path"],
                );
                row.fields.insert("Interpretation".into(), "Executable path bytes with directory context; the drive or original root is unverified. This does not establish file presence, ownership or recoverability.".into());
                partial_rows.push(row);
            } else {
                rows.push(row);
            }
            if rows.len() == MAX_PATHS {
                rows.extend(partial_rows);
                return Ok(rows);
            }
        }
        processed = base + end as u64;
        if n == 0 {
            break;
        }
        let discard = buffer.len().saturating_sub(WINDOW + 16);
        buffer.drain(..discard);
        base += discard as u64;
        progress(format!(
            "Searching executable path references: {} MiB",
            (base + buffer.len() as u64) / 1048576
        ));
    }
    rows.extend(partial_rows);
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_paths_need_directory_context_and_a_plausible_basename() {
        for name in [
            r"\\server\share\payload.exe",
            r"\Device\HarddiskVolume2\Windows\runas.exe",
            r"Users\name\Downloads\payload.exe",
            r".\tools\helper.exe",
        ] {
            assert_eq!(partial_path(name), Some(name));
        }
        for name in [
            "payload.exe",
            r"x\a.exe",
            r"x\123456.exe",
            r"C:\bad.exe",
            r"\\x\share\payload.exe",
            r"Users\\payload.exe",
            r"junk?|\payload.exe",
            r"x\payload.exe.config",
        ] {
            assert!(partial_path(name).is_none(), "{name}");
        }
    }

    #[test]
    fn partial_path_flood_does_not_consume_the_strict_budget() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = Vec::new();
        for n in 0..MAX_PARTIAL_PATHS + 10 {
            bytes.extend(format!("Users\\name\\helper{n}.exe\0").as_bytes());
        }
        bytes.extend(br"C:\Windows\strict.exe");
        std::fs::write(temp.path(), bytes).unwrap();
        let rows = scan(temp.path(), &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(rows.len(), MAX_PARTIAL_PATHS + 1);
        assert!(!rows[0].is_partial_match());
        assert_eq!(rows[0].text("Name"), r"C:\Windows\strict.exe");
    }

    #[test]
    fn partial_paths_preserve_offsets_in_each_encoding_without_hiding_strict_paths() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = Vec::new();
        let mut expected = Vec::new();
        for (encoding, name) in [
            r"\\server\share\payload.exe",
            r"\Device\HarddiskVolume2\runas.exe",
            r"Users\name\helper.exe",
        ]
        .into_iter()
        .enumerate()
        {
            let at = bytes.len();
            if encoding == 0 {
                bytes.extend(name.as_bytes());
            } else {
                bytes.extend(name.encode_utf16().flat_map(|c| {
                    if encoding == 1 {
                        c.to_le_bytes()
                    } else {
                        c.to_be_bytes()
                    }
                }));
            }
            bytes.extend([0; 8]);
            expected.push((name, at as u64));
        }
        bytes.extend(br"C:\Windows\strict.exe");
        std::fs::write(temp.path(), &bytes).unwrap();
        let rows = scan(temp.path(), &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(rows.len(), 4);
        assert!(!rows[0].is_partial_match());
        for ((name, offset), row) in expected.into_iter().zip(&rows[1..]) {
            assert!(row.is_partial_match());
            assert_eq!(row.text("Name"), name);
            let at = row.fields["Evidence offset"].as_u64().unwrap();
            // ASCII UTF-16 can have an indistinguishable shifted byte-order
            // interpretation. The retained encoding must reproduce its bytes.
            assert!(at.abs_diff(offset) <= 1);
            let encoded: Vec<_> = match row.text("Encoding").as_str() {
                "UTF-8" => name.as_bytes().to_vec(),
                "UTF-16LE" => name.encode_utf16().flat_map(u16::to_le_bytes).collect(),
                "UTF-16BE" => name.encode_utf16().flat_map(u16::to_be_bytes).collect(),
                _ => unreachable!(),
            };
            assert_eq!(&bytes[at as usize..at as usize + encoded.len()], encoded);
        }
    }

    #[test]
    fn references_keep_physical_offsets_encodings_and_chunk_boundaries() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let names = [
            r"C:\Users\name\Documents\folder\runas.exe",
            r"D:\Unicode\試験.exe",
            r"E:\Other\UPPER.EXE",
        ];
        let mut bytes = vec![0; CHUNK - 20];
        let mut offsets = Vec::new();
        for (i, name) in names.iter().enumerate() {
            bytes.push(0);
            offsets.push(bytes.len() as u64);
            if i == 0 {
                bytes.extend_from_slice(name.as_bytes());
            } else {
                bytes.extend(name.encode_utf16().flat_map(|c| {
                    if i == 1 {
                        c.to_le_bytes()
                    } else {
                        c.to_be_bytes()
                    }
                }));
            }
            bytes.extend_from_slice(&[0; 8]);
        }
        bytes.extend_from_slice(br"C:\not-an-executable.exe.config");
        bytes.push(0);
        bytes.extend_from_slice(names[0].as_bytes());
        std::fs::write(temp.path(), bytes).unwrap();
        let rows = scan(temp.path(), &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(rows.len(), 3);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.text("Name"), names[i]);
            assert_eq!(row.fields["Evidence offset"].as_u64(), Some(offsets[i]));
            assert_eq!(row.text("Encoding"), ["UTF-8", "UTF-16LE", "UTF-16BE"][i]);
        }
        assert!(scan(temp.path(), &AtomicBool::new(true), &|_| {}).is_err());
    }
}
