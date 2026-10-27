//! Recover URL strings from PID-scoped dumps without treating them as visits.
use super::super::process_memory::DumpScope;
use super::super::{BROWSER, browser, record};
use crate::{
    artifacts::OperatingSystem,
    case::{CaseSnapshot, Evidence, Run, RunStatus},
    results::{Query, ResultStore},
    volatility::{Installation, Record, Table},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub(in crate::analysis) const MEMMAP: &str = "windows.memmap.Memmap";
const CHUNK: usize = 1024 * 1024;
const MAX_URL: usize = 8192;
const MAX_PROCESS_URLS: usize = 10_000;
const MAX_PARTIAL_URLS: usize = 1_000;

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
    document: &CaseSnapshot,
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
                && r.status.has_results()
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
    Ok(result)
}

/// Queue browser processes with page content, then parse all recovered browser data.
pub fn recovery_runs(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &Evidence,
    engine: &Installation,
    cancel: &AtomicBool,
) -> Result<Vec<Run>, String> {
    if evidence.operating_system != OperatingSystem::Windows {
        return Err("Browser process memory recovery currently requires Windows evidence".into());
    }
    let mut processes = processes(directory, document, &evidence.id, cancel)?;
    processes.retain(|_, process| !process.browser.is_empty());
    if processes.is_empty() {
        return Err("Collect browser processes first, then recover browser memory".into());
    }
    let mut runs = Vec::new();
    for process in processes
        .values()
        .filter(|p| !matches!(p.role, "GPU" | "Utility" | "Helper"))
    {
        cancelled(cancel)?;
        let arguments = if engine.user_memory_dumps {
            DumpScope::User
        } else {
            DumpScope::Full
        }
        .arguments(process.pid);
        if document.runs.iter().any(|r| {
            r.evidence_id == evidence.id
                && r.plugin == MEMMAP
                && DumpScope::from_arguments(&r.arguments, process.pid).is_some()
                && (matches!(r.status, RunStatus::Queued | RunStatus::Running)
                    || r.status.has_results()
                        && crate::object_store::exists(
                            &directory
                                .join("analyses")
                                .join(&r.id)
                                .join(format!("pid.{}.dmp", process.pid)),
                        ))
        }) {
            continue;
        }
        runs.push(engine.prepare(evidence, MEMMAP, arguments, &directory.join("analyses"))?);
    }
    if runs.len() > 128 {
        return Err("More than 128 browser processes found. Recover selected PIDs using Memmap --pid <PID> --dump in New analysis.".into());
    }
    runs.push(super::super::prepare(evidence, BROWSER, vec![])?);
    Ok(runs)
}

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Browser analysis cancelled".into())
    } else {
        Ok(())
    }
}

use super::super::process_memory::{Region, regions};

struct Hit {
    address: u64,
    offset: u64,
    encoding: &'static str,
    complete: bool,
    count: usize,
    partial: bool,
}

#[derive(Default)]
struct UrlLimits {
    strict: bool,
    partial: bool,
}

// Keep the exact string as the key: query strings and fragments can be evidence.
fn scan(
    file: &mut (impl Read + Seek),
    regions: &[Region],
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(BTreeMap<String, Hit>, UrlLimits), String> {
    let mut hits = BTreeMap::new();
    let mut strict_count = 0;
    let mut partial_count = 0;
    let mut limits = UrlLimits::default();
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
                if let Some((url, encoding, complete, partial)) =
                    url_at(&buffer[at..], remaining == 0)
                {
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
                        if partial && partial_count >= MAX_PARTIAL_URLS {
                            limits.partial = true;
                            at += 1;
                            continue;
                        }
                        if partial {
                            partial_count += 1;
                        } else {
                            strict_count += 1;
                        }
                        hits.insert(
                            url,
                            Hit {
                                address: region.virtual_start + base + at as u64,
                                offset: region.file + base + at as u64,
                                encoding,
                                complete,
                                count: 1,
                                partial,
                            },
                        );
                    }
                    if strict_count >= MAX_PROCESS_URLS {
                        limits.strict = true;
                        return Ok((hits, limits));
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
    Ok((hits, limits))
}

fn url_at(bytes: &[u8], final_region: bool) -> Option<(String, &'static str, bool, bool)> {
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
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let partial = !host.contains('.') && host != "localhost";
    if partial && (!complete || !super::intranet_url(&url)) {
        return None;
    }
    Some((
        text,
        if wide { "UTF-16LE" } else { "UTF-8" },
        complete,
        partial,
    ))
}

pub(in crate::analysis) fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
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
            && r.status.has_results()
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
        let Some(scope) = DumpScope::from_arguments(&source.arguments, pid) else {
            continue;
        };
        let Some(process) = processes.get(&pid) else {
            warnings.push(format!("PID {pid}: skipped process dump because no supported browser identity is available in the current process inventory. Collect browser processes and analyze again."));
            continue;
        };
        if process.browser.is_empty() {
            // Network and application jobs also collect dumps. A known unrelated
            // process is outside Browser's scope, rather than missing coverage.
            if process.name.is_empty() {
                warnings.push(format!("PID {pid}: process identity is unreadable; browser coverage could not be determined. Collect process identities before running again."));
            }
            continue;
        }
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
            let (map, rejected) = regions(
                Table::read(&output.join("stdout.json"))?,
                &filename,
                total,
                scope,
            )?;
            let (hits, limits) = scan(&mut file, &map, cancel, progress)?;
            Ok((hits, limits, rejected))
        })();
        let (hits, limits, rejected) = match result {
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
        if limits.strict {
            warnings.push(format!(
                "PID {pid}: stopped at {MAX_PROCESS_URLS} unique strict URLs"
            ));
        }
        if limits.partial {
            warnings.push(format!("PID {pid}: partial URL limit reached ({MAX_PARTIAL_URLS}); strict recovery continued"));
        }
        let mut process_rows = Vec::new();
        for (url, hit) in hits {
            let search = (hit.complete && !hit.partial)
                .then(|| browser::search_terms(&url))
                .flatten();
            let parsed_url = url::Url::parse(&url).map_err(|e| e.to_string())?;
            let parameters: Vec<_> = if hit.complete && !hit.partial {
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
                    json!(super::search::query_origin(&parsed_url)),
                );
            }
            if hit.partial {
                super::super::partial::mark(
                    &mut row,
                    "Browser intranet URL",
                    &["Hostname has no dot and is not localhost"],
                );
                row.fields.insert("Interpretation".into(), "A delimited HTTP(S) URL with a plausible intranet hostname and a nonempty path was recovered from browser memory. Host identity, navigation and user intent are unverified; query terms were not inferred.".into());
            }
            process_rows.push(row);
        }
        super::dedup::memory_searches(&mut process_rows);
        let mut remaining = browser::MAX_ROWS
            .saturating_sub(rows.iter().filter(|row| !row.is_partial_match()).count());
        rows.extend(process_rows.into_iter().filter(|row| {
            if row.is_partial_match() {
                return true;
            }
            if remaining == 0 {
                return false;
            }
            remaining -= 1;
            true
        }));
        let (strict_limited, partial_limited) =
            super::super::partial::bound(rows, usize::MAX, browser::MAX_PARTIAL_ROWS);
        if strict_limited || partial_limited {
            warnings.push("Browser report finding limit reached; strict and partial findings have independent budgets.".into());
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
        bytes.extend_from_slice(b"https://www.search.com/web?q=synthetic+test+query\0");
        let wide_offset = bytes.len() as u64;
        bytes.extend(
            "https://duckduckgo.com/?q=another+synthetic+query\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        file.write_all(&bytes).unwrap();
        let regions = vec![Region {
            file: 0,
            virtual_start: 0x1000,
            length: bytes.len() as u64,
        }];
        let (hits, limits) = scan(&mut file, &regions, &AtomicBool::new(false), &|_| {}).unwrap();
        assert!(!limits.strict && !limits.partial);
        assert_eq!(hits.len(), 2);
        let edge = &hits["https://www.search.com/web?q=synthetic+test+query"];
        assert_eq!(edge.address, 0x1000 + offset);
        assert_eq!(edge.count, 1);
        let tor = &hits["https://duckduckgo.com/?q=another+synthetic+query"];
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
        assert!(!hits.contains_key("https://www.search.com/web?q=synthetic+test+query"));
        assert!(scan(&mut file, &regions, &AtomicBool::new(true), &|_| {}).is_err());
    }

    #[test]
    fn mapping_rejects_missing_pages_and_coalesces_virtual_neighbors() {
        let table = Table::parse(r#"[{"File output":"pid.42.dmp","Offset in File":0,"Virtual":4096,"Size":4096},{"File output":"pid.42.dmp","Offset in File":4096,"Virtual":8192,"Size":4096}]"#).unwrap();
        let (merged, rejected) =
            regions(table.clone(), "pid.42.dmp", 8192, DumpScope::Full).unwrap();
        assert_eq!(rejected, 0);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].length, 8192);
        let (partial, rejected) = regions(table, "pid.42.dmp", 4096, DumpScope::Full).unwrap();
        assert_eq!(partial.len(), 1);
        assert_eq!(rejected, 1);
        let table = Table::parse(r#"[{"File output":"pid.42.dmp","Offset in File":0,"Virtual":4096,"Size":4096},{"File output":"pid.42.dmp","Offset in File":4096,"Virtual":200680602931200,"Size":4096}]"#).unwrap();
        let (user, rejected) = regions(table, "pid.42.dmp", 8192, DumpScope::Full).unwrap();
        assert_eq!(rejected, 0);
        assert_eq!(
            user.len(),
            1,
            "masked kernel addresses must never be attributed to a browser"
        );
        assert_eq!(user[0].length, 4096);
        let table = Table::parse(r#"[{"File output":"pid.42.dmp","Offset in File":0,"Virtual":4096,"Size":4096},{"File output":"pid.42.dmp","Offset in File":4096,"Virtual":2147483648,"Size":4096}]"#).unwrap();
        assert_eq!(
            regions(table, "pid.42.dmp", 8192, DumpScope::Full)
                .unwrap()
                .0
                .len(),
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

    #[test]
    fn partial_urls_need_a_delimiter_hostname_and_path() {
        assert!(url_at(b"https://intranet/reports\0", true).unwrap().3);
        for bytes in [
            b"http://intranet/\0".as_slice(),
            b"http://xy/login\0",
            b"http://123a/login\0",
            b"http://-broken/login\0",
            b"http://user:pass@intranet/login\0",
            b"http://intranet/login",
        ] {
            assert!(url_at(bytes, true).is_none(), "{bytes:?}");
        }
        assert!(!url_at(b"https://example.org/path\0", true).unwrap().3);
    }

    #[test]
    fn intranet_flood_does_not_stop_later_public_urls() {
        let mut bytes = Vec::new();
        for n in 0..MAX_PARTIAL_URLS + 10 {
            bytes.extend(format!("http://intranet/report/{n}\0").as_bytes());
        }
        let offset = bytes.len();
        bytes.extend(b"https://example.org/strict\0");
        let range = Region {
            file: 0,
            virtual_start: 0x1000,
            length: bytes.len() as u64,
        };
        let (hits, limits) = scan(
            &mut std::io::Cursor::new(bytes),
            &[range],
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert!(limits.partial);
        assert!(!limits.strict);
        assert_eq!(hits.len(), MAX_PARTIAL_URLS + 1);
        assert_eq!(hits["https://example.org/strict"].offset, offset as u64);
        assert!(!hits["https://example.org/strict"].partial);
    }

    #[test]
    fn strict_limit_preserves_an_earlier_partial_overflow_diagnostic() {
        let mut bytes = Vec::new();
        for n in 0..MAX_PARTIAL_URLS + 1 {
            bytes.extend(format!("http://intranet/report/{n}\0").as_bytes());
        }
        for n in 0..MAX_PROCESS_URLS {
            bytes.extend(format!("https://example.org/{n}\0").as_bytes());
        }
        let range = Region {
            file: 0,
            virtual_start: 0x1000,
            length: bytes.len() as u64,
        };
        let (hits, limits) = scan(
            &mut std::io::Cursor::new(bytes),
            &[range],
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert!(limits.strict && limits.partial);
        assert_eq!(hits.len(), MAX_PROCESS_URLS + MAX_PARTIAL_URLS);
    }
}
