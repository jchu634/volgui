use super::{record, table};
use crate::volatility::Table;
use std::{
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub const MAX_HITS: usize = 10_000;
const CHUNK: usize = 1024 * 1024;

pub fn validate(arguments: &[String]) -> Result<(), String> {
    if arguments.is_empty() || arguments[0].is_empty() {
        return Err("Enter a literal string to search for".into());
    }
    if arguments[0].len() > 4096 {
        return Err("Search strings are limited to 4096 UTF-8 bytes".into());
    }
    if arguments.len() > 2 || arguments.get(1).is_some_and(|s| s != "--ignore-ascii-case") {
        return Err("Unsupported string search options".into());
    }
    Ok(())
}

pub fn search(
    path: &Path,
    arguments: &[String],
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    validate(arguments)?;
    let text = &arguments[0];
    let insensitive = arguments.len() == 2;
    let patterns = [
        text.as_bytes().to_vec(),
        text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    ];
    // Fold only ASCII characters, never bytes belonging to a non-ASCII UTF-16 unit.
    let masks: Vec<Vec<bool>> = (0..3)
        .map(|encoding| match encoding {
            0 => patterns[0].iter().map(u8::is_ascii_alphabetic).collect(),
            1 => patterns[1]
                .chunks_exact(2)
                .flat_map(|b| [b[1] == 0 && b[0].is_ascii_alphabetic(), false])
                .collect(),
            _ => patterns[2]
                .chunks_exact(2)
                .flat_map(|b| [false, b[0] == 0 && b[1].is_ascii_alphabetic()])
                .collect(),
        })
        .collect();
    let overlap = patterns.iter().map(Vec::len).max().unwrap() + 128;
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let total = file.metadata().map_err(|e| e.to_string())?.len();
    let mut buffer = Vec::with_capacity(CHUNK + overlap);
    let mut chunk = vec![0; CHUNK];
    let mut base = 0u64;
    let mut processed = [0u64; 3];
    let mut rows = Vec::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("String search cancelled".into());
        }
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        buffer.extend_from_slice(&chunk[..n]);
        let eof = n == 0;
        for (encoding, pattern) in patterns.iter().enumerate() {
            let end = if eof {
                buffer
                    .len()
                    .saturating_sub(pattern.len())
                    .saturating_add(usize::from(buffer.len() >= pattern.len()))
            } else {
                buffer.len().saturating_sub(overlap)
            };
            let mut start = processed[encoding].saturating_sub(base) as usize;
            while start < end {
                if start.is_multiple_of(4096) && cancel.load(Ordering::Relaxed) {
                    return Err("String search cancelled".into());
                }
                let at = if insensitive {
                    let first = pattern[0];
                    let candidate = if masks[encoding][0] {
                        memchr::memchr2(
                            first.to_ascii_lowercase(),
                            first.to_ascii_uppercase(),
                            &buffer[start..end],
                        )
                    } else {
                        memchr::memchr(first, &buffer[start..end])
                    };
                    candidate.map(|i| i + start)
                } else {
                    memchr::memmem::find(
                        &buffer[start..(end + pattern.len() - 1).min(buffer.len())],
                        pattern,
                    )
                    .map(|i| i + start)
                };
                let Some(at) = at.filter(|at| *at < end && *at + pattern.len() <= buffer.len())
                else {
                    break;
                };
                start = at + 1;
                if insensitive
                    && !buffer[at..at + pattern.len()]
                        .iter()
                        .zip(pattern)
                        .zip(&masks[encoding])
                        .all(|((a, b), fold)| {
                            if *fold {
                                a.eq_ignore_ascii_case(b)
                            } else {
                                a == b
                            }
                        })
                {
                    continue;
                }
                let step = if encoding == 0 { 1 } else { 2 };
                let left = at.saturating_sub(64 / step * step);
                let left = if step == 2 {
                    left + ((at - left) % 2)
                } else {
                    left
                };
                let right = (at + pattern.len() + 64).min(buffer.len());
                let bytes = &buffer[left..right];
                let context = match encoding {
                    0 => String::from_utf8_lossy(bytes).into_owned(),
                    1 => String::from_utf16_lossy(
                        &bytes
                            .chunks_exact(2)
                            .map(|b| u16::from_le_bytes([b[0], b[1]]))
                            .collect::<Vec<_>>(),
                    ),
                    _ => String::from_utf16_lossy(
                        &bytes
                            .chunks_exact(2)
                            .map(|b| u16::from_be_bytes([b[0], b[1]]))
                            .collect::<Vec<_>>(),
                    ),
                }
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect::<String>();
                let encoding_name = ["UTF-8", "UTF-16LE", "UTF-16BE"][encoding];
                rows.push(record(serde_json::json!({"Offset": base + at as u64, "Encoding": encoding_name, "Match": text, "Context": context, "Source file": path.display().to_string()})));
                if rows.len() == MAX_HITS {
                    rows.sort_by_key(|r| r.fields["Offset"].as_u64());
                    return Ok((
                        table(rows).with_warnings(vec![format!("Stopped at {MAX_HITS} matches. Narrow the string; rerunning the same search uses the same limit.")]),
                        format!(
                            "Stopped at {MAX_HITS} matches. Narrow the string and run again. Offsets refer to the evidence file, not virtual addresses."
                        ),
                    ));
                }
            }
            processed[encoding] = base + end as u64;
        }
        if eof {
            break;
        }
        let keep = overlap.min(buffer.len());
        let discard = buffer.len() - keep;
        buffer.drain(..discard);
        base += discard as u64;
        progress(format!(
            "String search: {} / {} MiB",
            (base + keep as u64) / 1048576,
            total / 1048576
        ));
    }
    rows.sort_by_key(|r| r.fields["Offset"].as_u64());
    let message = format!(
        "{} matches. Searched {total} bytes as UTF-8, UTF-16LE and UTF-16BE. Offsets refer to the evidence file, not virtual addresses.",
        rows.len()
    );
    Ok((table(rows), message))
}
