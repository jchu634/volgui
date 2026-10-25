//! Recover URL strings from PID-scoped dumps without treating them as visits.
use super::{BROWSER, browser, record};
use crate::{
    artifacts::OperatingSystem,
    case::{CaseDocument, Evidence, Run, RunStatus},
    results::{Query, ResultStore},
    volatility::{Installation, Record, Table},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub(super) const MEMMAP: &str = "windows.memmap.Memmap";
const CHUNK: usize = 1024 * 1024;
const MAX_URL: usize = 8192;
const MAX_PROCESS_URLS: usize = 10_000;

#[derive(Default)]
struct Process {
    pid: u64,
    parent: Option<u64>,
    name: String,
    command: String,
    browser: String,
    role: &'static str,
}

fn number(row: &Record, field: &str) -> Option<u64> {
    let value = row.fields.get(field)?;
    value.as_u64().or_else(|| {
        let text = value.as_str()?;
        text.strip_prefix("0x")
            .map(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or_else(|| text.parse().ok())
    })
}

fn processes(
    directory: &Path,
    document: &CaseDocument,
    evidence: &str,
    cancel: &AtomicBool,
) -> Result<BTreeMap<u64, Process>, String> {
    let mut seen = BTreeSet::new();
    let runs: Vec<_> = document
        .runs
        .iter()
        .rev()
        .filter(|r| {
            r.evidence_id == evidence
                && r.status == RunStatus::Completed
                && matches!(
                    r.plugin.as_str(),
                    "windows.pslist.PsList" | "windows.cmdline.CmdLine"
                )
                && seen.insert(r.plugin.clone())
        })
        .map(|r| r.id.clone())
        .collect();
    let mut result: BTreeMap<u64, Process> = BTreeMap::new();
    if runs.is_empty() {
        return Ok(result);
    }
    let store = ResultStore::at(directory);
    let index = store.query(&Query {
        runs,
        ..Default::default()
    })?;
    for ids in index.ids.chunks(256) {
        cancelled(cancel)?;
        for stored in store.fetch(ids)? {
            let row = stored.record;
            let Some(pid) = number(&row, "PID") else {
                continue;
            };
            let process = result.entry(pid).or_default();
            process.pid = pid;
            if let Some(parent) = number(&row, "PPID") {
                process.parent = Some(parent);
            }
            let name = ["ImageFileName", "Process"]
                .iter()
                .map(|key| row.text(key))
                .find(|s| !s.is_empty());
            if let Some(name) = name {
                process.name = name;
            }
            if let Some(command) = row.fields.get("Args").and_then(|v| v.as_str()) {
                process.command = command.into();
            }
        }
    }
    for process in result.values_mut() {
        let name = process.name.to_ascii_lowercase();
        let command = process.command.to_ascii_lowercase();
        process.browser = match name.as_str() {
            "msedge.exe" => "Edge",
            "chrome.exe" => "Chrome",
            "brave.exe" => "Brave",
            "opera.exe" => "Opera",
            "firefox.exe" if browser::browser_name(&command) == "Tor Browser" => "Tor Browser",
            "firefox.exe" => "Firefox",
            _ => "",
        }
        .into();
        process.role = if command.contains("--type=renderer") {
            "Renderer"
        } else if command.contains("--type=gpu-process") || command.ends_with(" gpu") {
            "GPU"
        } else if command.contains("--type=utility")
            || command.ends_with(" utility")
            || command.ends_with(" rdd")
        {
            "Utility"
        } else if command.contains("-contentproc") && command.ends_with(" tab") {
            "Content"
        } else if command.contains("-contentproc") {
            "Helper"
        } else if command.is_empty() {
            "Unknown"
        } else {
            "Browser"
        };
    }
    // Some content processes have an unreadable command line. Use the actual parent,
    // never the mere presence of another Tor process in the capture.
    for _ in 0..result.len() {
        let tor_children: Vec<_> = result
            .values()
            .filter(|p| {
                p.browser == "Firefox"
                    && p.parent
                        .and_then(|id| result.get(&id))
                        .is_some_and(|parent| parent.browser == "Tor Browser")
            })
            .map(|p| p.pid)
            .collect();
        if tor_children.is_empty() {
            break;
        }
        for id in tor_children {
            result.get_mut(&id).unwrap().browser = "Tor Browser".into();
        }
    }
    result.retain(|_, p| !p.browser.is_empty());
    Ok(result)
}

/// Queue browser processes with page content, then parse all recovered browser data.
pub fn recovery_runs(
    directory: &Path,
    document: &CaseDocument,
    evidence: &Evidence,
    engine: &Installation,
    cancel: &AtomicBool,
) -> Result<Vec<Run>, String> {
    if evidence.operating_system != OperatingSystem::Windows {
        return Err("Browser process memory recovery currently requires Windows evidence".into());
    }
    let processes = processes(directory, document, &evidence.id, cancel)?;
    if processes.is_empty() {
        return Err("Collect browser processes first, then recover browser memory".into());
    }
    let mut runs = Vec::new();
    for process in processes
        .values()
        .filter(|p| !matches!(p.role, "GPU" | "Utility" | "Helper"))
    {
        cancelled(cancel)?;
        let arguments = vec!["--pid".into(), process.pid.to_string(), "--dump".into()];
        if document.runs.iter().any(|r| {
            r.evidence_id == evidence.id
                && r.plugin == MEMMAP
                && r.arguments == arguments
                && (matches!(r.status, RunStatus::Queued | RunStatus::Running)
                    || r.status == RunStatus::Completed
                        && directory
                            .join("analyses")
                            .join(&r.id)
                            .join(format!("pid.{}.dmp", process.pid))
                            .is_file())
        }) {
            continue;
        }
        runs.push(engine.prepare(evidence, MEMMAP, arguments, &directory.join("analyses"))?);
    }
    if runs.len() > 128 {
        return Err("More than 128 browser processes found. Recover selected PIDs using Memmap --pid <PID> --dump in New analysis.".into());
    }
    runs.push(super::prepare(evidence, BROWSER, vec![])?);
    Ok(runs)
}

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Browser analysis cancelled".into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Region {
    file: u64,
    virtual_start: u64,
    length: u64,
}

fn regions(table: Table, filename: &str, total: u64) -> Result<(Vec<Region>, usize), String> {
    let user_end = if table
        .rows
        .iter()
        .any(|row| number(row, "Virtual").is_some_and(|v| v > u64::from(u32::MAX)))
    {
        1 << 47
    } else {
        // Conservatively use the default 2 GiB user range for 32-bit Windows.
        1 << 31
    };
    let mut regions = Vec::new();
    let mut rejected = 0;
    for row in table
        .rows
        .iter()
        .filter(|r| r.text("File output") == filename)
    {
        let (Some(file), Some(virtual_start), Some(length)) = (
            number(row, "Offset in File"),
            number(row, "Virtual"),
            number(row, "Size"),
        ) else {
            rejected += 1;
            continue;
        };
        // Memmap also emits shared kernel mappings. Intel layers can report them
        // with their upper sign-extension bits removed, so test bit 47 rather
        // than just looking for a 0xffff prefix. Those bytes cannot identify a
        // browser's activity. Windows user addresses occupy the lower half.
        if virtual_start >= user_end {
            continue;
        }
        if length == 0
            || file.checked_add(length).is_none_or(|end| end > total)
            || virtual_start
                .checked_add(length)
                .is_none_or(|end| end > user_end)
        {
            rejected += 1;
            continue;
        }
        regions.push(Region {
            file,
            virtual_start,
            length,
        });
    }
    regions.sort_by_key(|r| r.file);
    let mut merged: Vec<Region> = Vec::new();
    for region in regions {
        if let Some(last) = merged.last_mut() {
            if last.file + last.length > region.file {
                rejected += 1;
                continue;
            }
            if last.file + last.length == region.file
                && last.virtual_start + last.length == region.virtual_start
            {
                last.length += region.length;
                continue;
            }
        }
        merged.push(region);
    }
    if merged.is_empty() {
        return Err(format!(
            "No readable Memmap ranges for this PID; rejected {rejected} invalid ranges"
        ));
    }
    Ok((merged, rejected))
}

struct Hit {
    address: u64,
    offset: u64,
    encoding: &'static str,
    complete: bool,
    count: usize,
}

// Keep the exact string as the key: query strings and fragments can be evidence.
fn scan(
    file: &mut File,
    regions: &[Region],
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(BTreeMap<String, Hit>, bool), String> {
    let mut hits = BTreeMap::new();
    let mut chunk = vec![0; CHUNK];
    let mut buffer = Vec::with_capacity(CHUNK + MAX_URL);
    let mut last_progress = Instant::now();
    for region in regions {
        cancelled(cancel)?;
        file.seek(SeekFrom::Start(region.file))
            .map_err(|e| e.to_string())?;
        buffer.clear();
        let mut remaining = region.length;
        let mut base = 0u64;
        loop {
            cancelled(cancel)?;
            let count = remaining.min(CHUNK as u64) as usize;
            file.read_exact(&mut chunk[..count])
                .map_err(|e| e.to_string())?;
            remaining -= count as u64;
            buffer.extend_from_slice(&chunk[..count]);
            let end = if remaining == 0 {
                buffer.len()
            } else {
                buffer.len().saturating_sub(MAX_URL)
            };
            let mut at = 0;
            while at < end {
                let Some(found) = memchr::memchr(b'h', &buffer[at..end]) else {
                    break;
                };
                at += found;
                if at.is_multiple_of(4096) {
                    cancelled(cancel)?;
                }
                if let Some((url, encoding, complete)) = url_at(&buffer[at..], remaining == 0) {
                    if let Some(hit) = hits.get_mut(&url) {
                        let hit: &mut Hit = hit;
                        hit.count += 1;
                        if complete && !hit.complete {
                            hit.complete = true;
                            hit.address = region.virtual_start + base + at as u64;
                            hit.offset = region.file + base + at as u64;
                            hit.encoding = encoding;
                        }
                    } else {
                        hits.insert(
                            url,
                            Hit {
                                address: region.virtual_start + base + at as u64,
                                offset: region.file + base + at as u64,
                                encoding,
                                complete,
                                count: 1,
                            },
                        );
                    }
                    if hits.len() >= MAX_PROCESS_URLS {
                        return Ok((hits, true));
                    }
                }
                at += 1;
            }
            if remaining == 0 {
                break;
            }
            buffer.drain(..end);
            base += end as u64;
        }
        if last_progress.elapsed() >= Duration::from_millis(500) {
            progress(format!(
                "Scanning browser memory: {} unique URLs",
                hits.len()
            ));
            last_progress = Instant::now();
        }
    }
    Ok((hits, false))
}

fn url_at(bytes: &[u8], final_region: bool) -> Option<(String, &'static str, bool)> {
    let wide = bytes.starts_with(b"h\0t\0t\0p\0");
    if !wide && !bytes.starts_with(b"http://") && !bytes.starts_with(b"https://") {
        return None;
    }
    let step = if wide { 2 } else { 1 };
    let mut text = Vec::new();
    let mut at = 0;
    while at + step <= bytes.len() && at < MAX_URL {
        let byte = bytes[at];
        if wide && bytes[at + 1] != 0
            || !byte.is_ascii_graphic()
            || matches!(
                byte,
                b'"' | b'\'' | b'<' | b'>' | b'`' | b'{' | b'}' | b'\\' | b'^' | b'|'
            )
        {
            break;
        }
        text.push(byte);
        at += step;
    }
    let complete = at < MAX_URL && at + step <= bytes.len();
    if !complete && !final_region && bytes.len() < MAX_URL {
        return None;
    }
    let text = String::from_utf8(text).ok()?;
    let url = url::Url::parse(&text).ok()?;
    let host = url.host_str()?;
    if !matches!(url.scheme(), "http" | "https")
        || (!host.contains('.') && host != "localhost")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some((text, if wide { "UTF-16LE" } else { "UTF-8" }, complete))
}

pub(super) fn analyze(
    directory: &Path,
    document: &CaseDocument,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
    rows: &mut Vec<Record>,
    warnings: &mut Vec<String>,
) -> Result<usize, String> {
    let processes = processes(directory, document, &run.evidence_id, cancel)?;
    let mut seen = BTreeSet::new();
    let mut parsed = 0;
    for source in document.runs.iter().rev().filter(|r| {
        r.evidence_id == run.evidence_id
            && r.plugin == MEMMAP
            && r.status == RunStatus::Completed
            && r.arguments.iter().any(|s| s == "--dump")
    }) {
        cancelled(cancel)?;
        let Some(pid) = source
            .arguments
            .windows(2)
            .find(|a| a[0] == "--pid")
            .and_then(|a| a[1].parse::<u64>().ok())
        else {
            continue;
        };
        let Some(process) = processes.get(&pid) else {
            warnings.push(format!("PID {pid}: skipped process dump because no supported browser identity is available in the current process inventory. Collect browser processes and analyze again."));
            continue;
        };
        if !seen.insert(pid) {
            continue;
        }
        let output = directory.join("analyses").join(&source.id);
        let filename = format!("pid.{pid}.dmp");
        let path = output.join(&filename);
        progress(format!("Scanning {} PID {pid}", process.browser));
        let result: Result<_, String> = (|| {
            let mut file = match crate::extracted_files::open_artifact(&path) {
                Ok(file) => file,
                Err(error) => {
                    rows.push(browser::blocked_artifact(
                        directory, &source.id, &path, &error,
                    ));
                    return Err(error);
                }
            };
            let total = file.metadata().map_err(|e| e.to_string())?.len();
            let (map, rejected) =
                regions(Table::read(&output.join("stdout.json"))?, &filename, total)?;
            let (hits, limited) = scan(&mut file, &map, cancel, progress)?;
            Ok((hits, limited, rejected))
        })();
        let (hits, limited, rejected) = match result {
            Ok(result) => result,
            Err(error) => {
                cancelled(cancel)?;
                warnings.push(format!("PID {pid}: {error}"));
                continue;
            }
        };
        parsed += 1;
        if rejected > 0 {
            warnings.push(format!("PID {pid}: skipped {rejected} invalid, overlapping or truncated mapping ranges; retained other readable ranges."));
        }
        if limited {
            warnings.push(format!(
                "PID {pid}: stopped at {MAX_PROCESS_URLS} unique URLs"
            ));
        }
        for (url, hit) in hits {
            if rows.len() >= browser::MAX_ROWS {
                break;
            }
            let search = hit.complete.then(|| browser::search_terms(&url)).flatten();
            let parsed_url = url::Url::parse(&url).map_err(|e| e.to_string())?;
            let parameters: Vec<_> = if hit.complete {
                parsed_url
                    .query_pairs()
                    .map(|(name, value)| json!({"Name":name,"Value":value}))
                    .collect()
            } else {
                Vec::new()
            };
            let mut row = record(json!({
                "Kind": if search.is_some() { "Memory search" } else { "Memory URL" },
                "Browser": process.browser, "PID":pid, "Process":process.name,
                "Process role":process.role, "Command line":process.command,
                "URL":url, "Domain":parsed_url.host_str().unwrap_or_default(), "URL parameters":parameters,
                "Virtual address":format!("{:#x}", hit.address), "Dump offset":hit.offset,
                "Encoding":hit.encoding, "Occurrences":hit.count,
                "String boundary":if hit.complete { "Delimiter found; adjacent text may be included" } else { "Region boundary or length limit; may be truncated" },
                "Attribution":"URL bytes in process user memory", "Source run":source.id,
                "Source file":path.strip_prefix(directory).unwrap_or(&path).display().to_string(),
                "Observation":"Memory strings can be stale, embedded resources, suggestions or prefetched URLs. They do not alone establish a visit, user intent or capture-time tab state. No visit timestamp recovered."
            }));
            if let Some((engine, terms)) = search {
                row.fields.insert("Search engine".into(), json!(engine));
                row.fields.insert("Search terms".into(), json!(terms));
                row.fields.insert(
                    "Query origin".into(),
                    json!(super::browser_search::query_origin(&parsed_url)),
                );
            }
            rows.push(row);
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_preserves_searches_across_chunks_and_contiguous_pages_only() {
        let mut file = tempfile::tempfile().unwrap();
        use std::io::Write;
        let mut bytes = vec![0; CHUNK - 12];
        let offset = bytes.len() as u64;
        bytes.extend_from_slice(b"https://www.search.com/web?q=what+is+gluten\0");
        let wide_offset = bytes.len() as u64;
        bytes.extend(
            "https://duckduckgo.com/?q=making+up+a+story\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        file.write_all(&bytes).unwrap();
        let regions = vec![Region {
            file: 0,
            virtual_start: 0x1000,
            length: bytes.len() as u64,
        }];
        let (hits, limited) = scan(&mut file, &regions, &AtomicBool::new(false), &|_| {}).unwrap();
        assert!(!limited);
        assert_eq!(hits.len(), 2);
        let edge = &hits["https://www.search.com/web?q=what+is+gluten"];
        assert_eq!(edge.address, 0x1000 + offset);
        assert_eq!(edge.count, 1);
        let tor = &hits["https://duckduckgo.com/?q=making+up+a+story"];
        assert_eq!(tor.offset, wide_offset);
        assert_eq!(tor.encoding, "UTF-16LE");
        let regions = vec![
            Region {
                file: 0,
                virtual_start: 0,
                length: CHUNK as u64,
            },
            Region {
                file: CHUNK as u64,
                virtual_start: 0x900000,
                length: bytes.len() as u64 - CHUNK as u64,
            },
        ];
        let (hits, _) = scan(&mut file, &regions, &AtomicBool::new(false), &|_| {}).unwrap();
        assert!(!hits.contains_key("https://www.search.com/web?q=what+is+gluten"));
        assert!(scan(&mut file, &regions, &AtomicBool::new(true), &|_| {}).is_err());
    }

    #[test]
    fn mapping_rejects_missing_pages_and_coalesces_virtual_neighbors() {
        let table = Table::parse(r#"[{"File output":"pid.42.dmp","Offset in File":0,"Virtual":4096,"Size":4096},{"File output":"pid.42.dmp","Offset in File":4096,"Virtual":8192,"Size":4096}]"#).unwrap();
        let (merged, rejected) = regions(table.clone(), "pid.42.dmp", 8192).unwrap();
        assert_eq!(rejected, 0);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].length, 8192);
        let (partial, rejected) = regions(table, "pid.42.dmp", 4096).unwrap();
        assert_eq!(partial.len(), 1);
        assert_eq!(rejected, 1);
        let table = Table::parse(r#"[{"File output":"pid.42.dmp","Offset in File":0,"Virtual":4096,"Size":4096},{"File output":"pid.42.dmp","Offset in File":4096,"Virtual":200680602931200,"Size":4096}]"#).unwrap();
        let (user, rejected) = regions(table, "pid.42.dmp", 8192).unwrap();
        assert_eq!(rejected, 0);
        assert_eq!(
            user.len(),
            1,
            "masked kernel addresses must never be attributed to a browser"
        );
        assert_eq!(user[0].length, 4096);
        let table = Table::parse(r#"[{"File output":"pid.42.dmp","Offset in File":0,"Virtual":4096,"Size":4096},{"File output":"pid.42.dmp","Offset in File":4096,"Virtual":2147483648,"Size":4096}]"#).unwrap();
        assert_eq!(
            regions(table, "pid.42.dmp", 8192).unwrap().0.len(),
            1,
            "32-bit kernel mappings must also be excluded"
        );
    }

    #[test]
    fn incomplete_strings_are_flagged_and_templates_are_not_searches() {
        assert!(
            !url_at(b"https://example.org/search?q=partial", true)
                .unwrap()
                .2
        );
        assert!(
            url_at(b"https://example.org/search?q=complete\0", true)
                .unwrap()
                .2
        );
        assert!(url_at(b"http://not-a-domain\0", true).is_none());
    }
}
