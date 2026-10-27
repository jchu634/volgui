mod dedup;
pub(super) mod memory;
mod profiles;
mod search;

use super::{record, table};
use crate::{
    case::{CaseSnapshot, Run},
    extracted_files,
    volatility::{Record, Table},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) const MAX_ROWS: usize = 100_000;
pub(super) const MAX_PARTIAL_ROWS: usize = 5_000;
const MAX_PARTIAL_SESSION_ROWS: usize = 2_000;
const SESSION_LIMIT: u64 = 32 * 1024 * 1024;

pub(super) fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    analyze_mode(directory, document, run, cancel, progress, true)
}

pub(super) fn analyze_profiles(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    analyze_mode(directory, document, run, cancel, progress, false)
}

fn analyze_mode(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
    include_memory: bool,
) -> Result<(Table, String), String> {
    let candidates = super::browser_candidates(directory, document, &run.evidence_id, cancel)?;
    let owners: BTreeMap<_, _> = document
        .runs
        .iter()
        .map(|r| (r.id.as_str(), r.plugin.as_str()))
        .collect();
    let mut originals_by_arguments: BTreeMap<Vec<String>, Vec<_>> = BTreeMap::new();
    for candidate in &candidates {
        if let Some(target) = owners.get(candidate.run_id.as_str()).and_then(|plugin| {
            extracted_files::FileDumpTarget::from_record(plugin, &candidate.record)
        }) {
            for arguments in [target.arguments(false), target.arguments(true)] {
                originals_by_arguments
                    .entry(arguments)
                    .or_default()
                    .push(candidate);
            }
        }
    }
    let reader = crate::object_store::ReadContext::new(directory)?;
    let mut reused = 0;
    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    let mut parsed = 0;
    let mut report_limits = (false, false);
    for source in document.runs.iter().filter(|r| {
        r.evidence_id == run.evidence_id && r.status.has_results() && !super::is_native(&r.plugin)
    }) {
        let output = directory.join("analyses").join(&source.id);
        if !output.is_dir() {
            continue;
        }
        if source.plugin != extracted_files::DUMP_FILES {
            continue;
        }
        let originals = originals_by_arguments
            .get(&source.arguments)
            .cloned()
            .unwrap_or_default();
        let original = originals.first().copied();
        let original_path = original
            .map(|r| {
                ["Name", "FileName", "Path"]
                    .iter()
                    .map(|key| r.record.text(key))
                    .find(|v| !v.is_empty())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        for path in extracted_files::list(&output)? {
            if cancel.load(Ordering::Relaxed) {
                return Err("Browser analysis cancelled".into());
            }
            let Some(profile_source) = profiles::Source::named(&original_path)
                .or_else(|| profiles::Source::recovered(&path))
            else {
                continue;
            };
            progress(format!(
                "Analyzing browser data: {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
            let (mut file, hash) = match extracted_files::open_in(&reader, &path) {
                Ok(file) => file,
                Err(error) => {
                    if profile_source == profiles::Source::Unknown {
                        continue;
                    }
                    rows.push(blocked_artifact(directory, &source.id, &path, &error));
                    warnings.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            let first = rows.len();
            let (profile, cached) =
                match profiles::read(&path, &mut file, hash.as_deref(), profile_source, cancel) {
                    Ok(profile) => profile,
                    Err(error) => {
                        if cancel.load(Ordering::Relaxed) {
                            return Err(error);
                        }
                        if profile_source == profiles::Source::Unknown {
                            continue;
                        }
                        rows.push(blocked_artifact(directory, &source.id, &path, &error));
                        warnings.push(format!("{}: {error}", path.display()));
                        continue;
                    }
                };
            reused += usize::from(cached);
            if let Some(error) = profile.error {
                warnings.push(format!("{}: {error}", path.display()));
            }
            rows.extend(profile.rows);
            if rows.len() > first {
                parsed += 1;
            }
            let browser = browser_name(&original_path);
            let pids: std::collections::BTreeSet<_> = originals
                .iter()
                .map(|r| r.record.text("PID"))
                .filter(|pid| pid.parse::<u64>().is_ok())
                .collect();
            for row in &mut rows[first..] {
                row.fields.insert("Source run".into(), json!(source.id));
                row.fields.insert(
                    "Source file".into(),
                    json!(
                        path.strip_prefix(directory)
                            .unwrap_or(&path)
                            .display()
                            .to_string()
                    ),
                );
                row.fields
                    .insert("Original path".into(), json!(original_path));
                if browser != "Unknown" {
                    row.fields.insert("Browser".into(), json!(browser));
                }
                row.fields.insert(
                    "Attribution".into(),
                    json!(if pids.is_empty() {
                        "Recovered profile file; no process attribution"
                    } else {
                        "File handle owner; does not identify which process performed a search"
                    }),
                );
                if pids.len() == 1 {
                    row.fields.insert(
                        "PID".into(),
                        json!(pids.first().unwrap().parse::<u64>().unwrap()),
                    );
                } else if !pids.is_empty() {
                    row.fields.insert(
                        "Related PIDs".into(),
                        json!(pids.iter().cloned().collect::<Vec<_>>().join(", ")),
                    );
                }
            }
            // Preserve the existing final kind-priority sort before truncating
            // strict profile results. Only partials are bounded during parsing.
            let limits = super::partial::bound(&mut rows, usize::MAX, MAX_PARTIAL_ROWS);
            report_limits.0 |= limits.0;
            report_limits.1 |= limits.1;
            if rows.iter().filter(|row| !row.is_partial_match()).count() >= MAX_ROWS {
                warnings.push(format!("Stopped at the {MAX_ROWS} row limit. Analyze fewer recovered files to narrow results."));
                break;
            }
        }
        if rows.iter().filter(|row| !row.is_partial_match()).count() >= MAX_ROWS {
            break;
        }
    }
    let memory = if include_memory {
        memory::analyze(
            directory,
            document,
            run,
            cancel,
            progress,
            &mut rows,
            &mut warnings,
        )?
    } else {
        0
    };
    rows.sort_by_key(|row| {
        (
            row.is_partial_match(),
            match row.text("Kind").as_str() {
                "Memory search" | "Web search" => 0,
                "Web history" | "Session tab" => 1,
                _ => 2,
            },
        )
    });
    let limits = super::partial::bound(&mut rows, MAX_ROWS, MAX_PARTIAL_ROWS);
    if report_limits.0
        || limits.0
        || rows.iter().filter(|row| !row.is_partial_match()).count() == MAX_ROWS
    {
        warnings.push(format!(
            "Stopped at the {MAX_ROWS} finding limit; some URLs may be omitted."
        ));
    }
    if report_limits.1 || limits.1 {
        warnings.push(format!("Partial browser report limit reached ({MAX_PARTIAL_ROWS} rows); strict recovery continued."));
    }
    let message = if !include_memory {
        format!(
            "Recovered {} profile findings from {parsed} cached files. Reused {reused} immutable artifact classifications or profiles. Standalone SQLite pages only; detached WAL pages are not merged.\n{}",
            rows.len(),
            warnings.join("\n")
        )
    } else {
        format!(
            "Recovered {} findings from {parsed} profile files and {memory} browser process dumps. Reused {reused} immutable artifact classifications or profiles. Memory URLs and searches show bytes in a PID, not proof of a visit or user intent. Repeated strings in each process are grouped by exact URL. Matching memory searches and query prefixes are grouped under the longest query within each process, source, endpoint and query origin. Search variants retain the original URLs, addresses and counts; Grouped occurrences totals those counts. Prefix grouping does not establish which queries were submitted. Session tabs reflect the saved session, not proof of a running browser. Only cached pages in standalone history databases are read; detached WAL pages are not merged.\n{}",
            rows.len(),
            warnings.join("\n")
        )
    };
    Ok((table(rows).with_warnings(warnings), message))
}

pub(super) fn blocked_artifact(directory: &Path, source: &str, path: &Path, error: &str) -> Record {
    let persisted = extracted_files::block_artifact(path, error);
    let blocked = extracted_files::ensure_openable(path).is_err();
    record(json!({
        "Kind": "Unavailable artifact",
        "Status": if blocked { "Potential malware / unavailable" } else { "Temporarily unavailable" },
        "Opening blocked": blocked,
        "Source run": source,
        "Source file": path.strip_prefix(directory).unwrap_or(path).display().to_string(),
        "Observation": format!("{error}. The artifact may have been quarantined, deleted or denied access. Malware is not confirmed by this error."),
        "Block record": persisted.err().unwrap_or_default(),
    }))
}

pub(super) fn browser_name(path: &str) -> &'static str {
    let path = path.to_lowercase();
    if path.contains("torbrowser") || path.contains("tor-browser") || path.contains("tor browser") {
        "Tor Browser"
    } else if path.contains("firefox") {
        "Firefox"
    } else if path.contains("edge") {
        "Edge"
    } else if path.contains("brave") {
        "Brave"
    } else if path.contains("chrome") {
        "Chrome"
    } else if path.contains("opera") {
        "Opera"
    } else {
        "Unknown"
    }
}

pub(super) fn timestamp(microseconds: i64, chrome: bool) -> String {
    let unix = if chrome {
        microseconds.checked_sub(11_644_473_600_000_000)
    } else {
        Some(microseconds)
    };
    unix.and_then(DateTime::<Utc>::from_timestamp_micros)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

pub(super) use search::search_terms;

/// A single-label authority needs explicit path context to survive relaxed URL
/// filtering. Bare scheme markers and numeric/garbled hostnames remain noise.
fn intranet_url(url: &url::Url) -> bool {
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    (3..=63).contains(&host.len())
        && !host.contains('.')
        && !host.starts_with('-')
        && !host.ends_with('-')
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && host.bytes().filter(u8::is_ascii_alphabetic).count() >= 2
        && url.path().len() > 1
}

fn session_candidate(
    rows: &mut Vec<Record>,
    browser: &str,
    address: &str,
    title: &str,
    observation: Value,
    failures: &[&str],
) {
    if rows.len() >= MAX_PARTIAL_SESSION_ROWS
        || address.len() > 4096
        || title.len() > 4096
        || address.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return;
    }
    let Ok(url) = url::Url::parse(address) else {
        return;
    };
    let Some(host) = url.host_str() else {
        return;
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || (!host.contains('.') && host != "localhost" && !intranet_url(&url))
    {
        return;
    }
    let mut row = record(json!({
        "Kind":"Session navigation candidate", "Browser":browser, "URL":address, "Title":title,
        "Observation":observation,
        "Interpretation":"Readable navigation entry without the state needed to recover a selected session tab. It does not establish a visit, active tab or submitted search."
    }));
    super::partial::mark(&mut row, "Browser session navigation", failures);
    rows.push(row);
}

fn push(
    rows: &mut Vec<Record>,
    kind: &str,
    browser: &str,
    url: String,
    title: String,
    time: Option<(i64, bool)>,
    observation: Value,
) {
    if rows.len() >= MAX_ROWS {
        return;
    }
    let raw_time = time.map(|t| t.0);
    let time = time
        .map(|(value, chrome)| timestamp(value, chrome))
        .unwrap_or_default();
    let mut row = record(
        json!({"Kind": kind, "Browser": browser, "URL": url, "Title": title, "Time (UTC)": time, "Raw timestamp": raw_time, "Observation": observation}),
    );
    if let Some((engine, terms)) = search_terms(&url) {
        row.fields.insert("Search engine".into(), json!(engine));
        row.fields.insert("Search terms".into(), json!(terms));
    }
    let search = row.fields.contains_key("Search terms");
    rows.push(row.clone());
    if search && rows.len() < MAX_ROWS {
        row.fields.insert("Kind".into(), json!("Web search"));
        rows.push(row);
    }
}

fn history(
    path: &Path,
    rows: &mut Vec<Record>,
    cancel: &AtomicBool,
    expected: bool,
) -> Result<(), String> {
    let db = crate::file_content::open_database(path)?;
    let mut budget = 0usize;
    db.progress_handler(
        1000,
        Some(move || {
            budget += 1000;
            budget > 20_000_000
        }),
    )
    .map_err(|e| e.to_string())?;
    if cancel.load(Ordering::Relaxed) {
        return Err("Browser analysis cancelled".into());
    }
    let has = |name: &str| {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|e| format!("Cannot read SQLite schema: {e}"))
    };
    let downloads = has("downloads")?;
    if downloads {
        super::downloads::chromium_downloads(&db, rows, cancel)?;
    }
    let (sql, browser, chrome) = if has("urls")? && has("visits")? {
        (
            "SELECT u.url, COALESCE(u.title,''), v.visit_time, v.id FROM visits v JOIN urls u ON u.id=v.url LIMIT 100000",
            "Chromium",
            true,
        )
    } else if has("moz_places")? && has("moz_historyvisits")? {
        (
            "SELECT p.url, COALESCE(p.title,''), v.visit_date, v.id FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id LIMIT 100000",
            "Firefox",
            false,
        )
    } else if downloads || !expected {
        return Ok(());
    } else {
        return Err("SQLite file has no supported Chromium or Firefox history tables".into());
    };
    let mut statement = db.prepare(sql).map_err(|e| e.to_string())?;
    let mut result = statement.query([]).map_err(|e| e.to_string())?;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Browser analysis cancelled".into());
        }
        let Some(row) = result
            .next()
            .map_err(|e| format!("Partial history recovery: {e}"))?
        else {
            break;
        };
        let address: String = row.get(0).map_err(|e| e.to_string())?;
        let title: String = row.get(1).map_err(|e| e.to_string())?;
        let time: i64 = row.get(2).map_err(|e| e.to_string())?;
        let id: i64 = row.get(3).map_err(|e| e.to_string())?;
        push(
            rows,
            "Web history",
            browser,
            address,
            title,
            Some((time, chrome)),
            json!({"Visit ID": id}),
        );
        if rows.len() >= MAX_ROWS {
            break;
        }
    }
    if chrome && has("keyword_search_terms")? {
        let mut statement = db.prepare("SELECT k.term, u.url, u.last_visit_time, k.keyword_id FROM keyword_search_terms k JOIN urls u ON u.id=k.url_id LIMIT 100000").map_err(|e| e.to_string())?;
        let mut result = statement.query([]).map_err(|e| e.to_string())?;
        while rows.len() < MAX_ROWS {
            if cancel.load(Ordering::Relaxed) {
                return Err("Browser analysis cancelled".into());
            }
            let Some(row) = result.next().map_err(|e| e.to_string())? else {
                break;
            };
            let terms: String = row.get(0).map_err(|e| e.to_string())?;
            let address: String = row.get(1).map_err(|e| e.to_string())?;
            let time: i64 = row.get(2).map_err(|e| e.to_string())?;
            let keyword: i64 = row.get(3).map_err(|e| e.to_string())?;
            rows.push(record(json!({"Kind":"Web search", "Browser":"Chromium", "URL":address, "Search terms":terms, "Time (UTC)":timestamp(time,true), "Raw timestamp":time, "Observation":{"Table":"keyword_search_terms", "Keyword ID":keyword, "Timestamp meaning":"URL last visit, not necessarily the search time"}})));
        }
    }
    Ok(())
}

fn read_session(path: &Path) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    extracted_files::open_artifact(path)
        .map_err(|e| e.to_string())?
        .take(SESSION_LIMIT + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > SESSION_LIMIT {
        return Err("Session file exceeds 32 MiB parser limit".into());
    }
    Ok(data)
}

fn firefox_session(data: &[u8], rows: &mut Vec<Record>) -> Result<(), String> {
    let value: Value =
        serde_json::from_slice(data).map_err(|e| format!("No readable session JSON: {e}"))?;
    let windows = value["windows"]
        .as_array()
        .ok_or("Session JSON has no windows")?;
    let mut partial_rows = Vec::new();
    for (w, window) in windows.iter().enumerate() {
        let Some(tabs) = window["tabs"].as_array() else {
            continue;
        };
        for (t, tab) in tabs.iter().enumerate() {
            let Some(entries) = tab["entries"].as_array() else {
                continue;
            };
            let selected = tab["index"].as_u64().and_then(|v| v.checked_sub(1));
            let selected_entry = selected
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| entries.get(index));
            let Some((index, entry, address)) =
                selected.zip(selected_entry).and_then(|(index, entry)| {
                    entry["url"].as_str().map(|address| (index, entry, address))
                })
            else {
                for (index, entry) in entries.iter().enumerate().rev().take(32) {
                    if let Some(address) = entry["url"].as_str() {
                        session_candidate(
                            &mut partial_rows,
                            "Firefox",
                            address,
                            entry["title"].as_str().unwrap_or(""),
                            json!({"Window":w+1,"Tab":t+1,"Navigation index":index+1,"State":"Selection not recovered"}),
                            &[
                                "Selected navigation index or selected entry is missing or unreadable",
                            ],
                        );
                    }
                }
                continue;
            };
            push(
                rows,
                "Session tab",
                "Firefox",
                address.into(),
                entry["title"].as_str().unwrap_or("").into(),
                None,
                json!({"Window":w + 1,"Tab":t + 1,"Navigation index":index + 1,"State":"Saved session"}),
            );
        }
    }
    let limited = partial_rows.len() == MAX_PARTIAL_SESSION_ROWS;
    rows.extend(partial_rows);
    if limited {
        Err("Partial session navigation limit reached; strict tabs were retained".into())
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct Tab {
    window: Option<i32>,
    selected: i32,
    navigation: BTreeMap<i32, (String, String)>,
}

fn int(data: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}
fn pickle_string(data: &[u8], at: &mut usize, wide: bool) -> Option<String> {
    let units = usize::try_from(int(data, *at)?).ok()?;
    *at += 4;
    let length = units.checked_mul(if wide { 2 } else { 1 })?;
    let bytes = data.get(*at..at.checked_add(length)?)?;
    *at = at.checked_add(length.checked_add(3)? & !3)?;
    if wide {
        Some(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        ))
    } else {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

fn chromium_session(data: &[u8], rows: &mut Vec<Record>) -> Result<(), String> {
    let version = int(data, 4).ok_or("Truncated Chromium session header")?;
    if !matches!(version, 1 | 3) {
        return Err(format!(
            "Chromium session version {version} is encrypted or unsupported"
        ));
    }
    let mut tabs: BTreeMap<i32, Tab> = BTreeMap::new();
    let mut closed_windows = HashSet::new();
    let mut closed_tabs = HashSet::new();
    let mut offset = 8;
    let mut truncated = false;
    while offset < data.len() {
        let Some(size) = data
            .get(offset..offset + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        else {
            truncated = true;
            break;
        };
        offset += 2;
        let Some(command) = data.get(offset..offset + size).filter(|c| !c.is_empty()) else {
            truncated = true;
            break;
        };
        offset += size;
        let payload = &command[1..];
        match command[0] {
            0 => {
                if let (Some(window), Some(tab)) = (int(payload, 0), int(payload, 4)) {
                    closed_tabs.remove(&tab);
                    tabs.entry(tab).or_default().window = Some(window);
                }
            }
            6 => {
                // SessionCommand's variable payload is a Pickle: size header, tab id, navigation index.
                if let (Some(tab), Some(index)) = (int(payload, 4), int(payload, 8)) {
                    let mut at = 12;
                    if let (Some(url), Some(title)) = (
                        pickle_string(payload, &mut at, false),
                        pickle_string(payload, &mut at, true),
                    ) {
                        tabs.entry(tab)
                            .or_default()
                            .navigation
                            .insert(index, (url, title));
                    }
                }
            }
            7 => {
                if let (Some(tab), Some(index)) = (int(payload, 0), int(payload, 4)) {
                    tabs.entry(tab).or_default().selected = index;
                }
            }
            16 => {
                if let Some(tab) = int(payload, 0) {
                    tabs.remove(&tab);
                    closed_tabs.insert(tab);
                }
            }
            17 => {
                if let Some(window) = int(payload, 0) {
                    closed_windows.insert(window);
                }
            }
            5 => {
                if let (Some(tab), Some(index)) = (int(payload, 0), int(payload, 4)) {
                    tabs.entry(tab)
                        .or_default()
                        .navigation
                        .retain(|i, _| *i < index);
                }
            }
            11 | 24 => {
                if let Some(tab) = int(payload, 0) {
                    let range = if command[0] == 11 {
                        int(payload, 4).map(|count| (0, count))
                    } else {
                        int(payload, 4).zip(int(payload, 8))
                    };
                    if let Some((start, count)) = range.filter(|(s, c)| *s >= 0 && *c > 0) {
                        let state = tabs.entry(tab).or_default();
                        state.navigation = std::mem::take(&mut state.navigation)
                            .into_iter()
                            .filter_map(|(i, v)| {
                                if i < start {
                                    Some((i, v))
                                } else if i >= start.saturating_add(count) {
                                    Some((i - count, v))
                                } else {
                                    None
                                }
                            })
                            .collect();
                    }
                }
            }
            _ => {}
        }
    }
    let mut partial_rows = Vec::new();
    for (id, tab) in tabs {
        if closed_tabs.contains(&id) || tab.window.is_some_and(|w| closed_windows.contains(&w)) {
            continue;
        }
        if let Some((url, title)) = tab
            .navigation
            .get(&tab.selected)
            .filter(|_| tab.window.is_some())
        {
            push(
                rows,
                "Session tab",
                "Chromium",
                url.clone(),
                title.clone(),
                None,
                json!({"Window":tab.window,"Tab":id,"Navigation index":tab.selected,"State":"Saved session"}),
            );
        } else {
            for (index, (url, title)) in tab.navigation.iter().rev().take(32) {
                if *index < 0 {
                    continue;
                }
                let mut failures = Vec::new();
                if tab.window.is_none() {
                    failures.push("Window association is missing");
                }
                if !tab.navigation.contains_key(&tab.selected) {
                    failures.push("Selected navigation entry is missing");
                }
                session_candidate(
                    &mut partial_rows,
                    "Chromium",
                    url,
                    title,
                    json!({"Window":tab.window,"Tab":id,"Navigation index":index,"State":"Selected tab not recovered"}),
                    &failures,
                );
            }
        }
    }
    let partial_limited = partial_rows.len() == MAX_PARTIAL_SESSION_ROWS;
    rows.extend(partial_rows);
    if truncated {
        Err("Session log is truncated; tabs reflect the readable prefix only".into())
    } else if partial_limited {
        Err("Partial session navigation limit reached; strict tabs were retained".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_history_schema_reports_sqlite_error_instead_of_missing_tables() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("History");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
            .unwrap();
        drop(db);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[100] = 0xff; // Invalid page type for sqlite_master's root b-tree.
        std::fs::write(&path, bytes).unwrap();
        let error = history(&path, &mut Vec::new(), &AtomicBool::new(false), true).unwrap_err();
        assert!(error.contains("Cannot read SQLite schema"), "{error}");
        assert!(error.contains("malformed"), "{error}");
        assert!(!error.contains("no supported"));
    }

    #[test]
    fn search_urls_require_real_provider_hosts_and_decode_terms() {
        assert_eq!(
            search_terms("https://www.google.com/search?q=memory%20forensics%2Btools"),
            Some(("Google".into(), "memory forensics+tools".into()))
        );
        assert!(search_terms("https://www.google.com.evil.test/search?q=bad").is_none());
        assert!(search_terms("https://example.org/?q=not+a+search").is_none());
        assert_eq!(
            search_terms("https://www.search.com/web?q=synthetic+test+query"),
            Some(("Search".into(), "synthetic test query".into()))
        );
        assert_eq!(
            search_terms(
                "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=another+synthetic+query"
            ),
            Some(("DuckDuckGo".into(), "another synthetic query".into()))
        );
        assert!(search_terms("https://duckduckgo.com/?q={searchTerms}").is_none());
        assert!(search_terms("https://duckduckgo.com/?q=%s").is_none());
        assert!(search_terms("https://duckduckgo.com/t.js?q=suggestion").is_none());
    }
    #[test]
    fn firefox_uses_selected_entry_and_excludes_closed_tabs() {
        let mut rows = vec![];
        firefox_session(br#"{"windows":[{"tabs":[{"index":1,"entries":[{"url":"https://current.test"},{"url":"https://forward.test"}]}],"_closedTabs":[{"url":"https://closed.test"}]}]}"#,&mut rows).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text("URL"), "https://current.test");
    }
    #[test]
    fn orphan_session_entries_are_partial_and_never_generate_search_findings() {
        let mut rows = Vec::new();
        firefox_session(br#"{"windows":[{"tabs":[{"entries":[{"url":"https://www.google.com/search?q=orphan"},{"url":"javascript:alert(1)"},{"url":"garbage"}]},{"index":1,"entries":[{"url":"https://strict.test"}]}],"_closedTabs":[{"entries":[{"url":"https://closed.test"}]}]}]}"#, &mut rows).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text("Kind"), "Session tab");
        assert!(rows[1].is_partial_match());
        assert_eq!(rows[1].text("Kind"), "Session navigation candidate");
        assert!(rows[1].text("Search terms").is_empty());
        assert!(!rows[1].text("Validation failures").is_empty());
    }

    #[test]
    fn chromium_partial_navigation_respects_closed_tabs_and_selected_state() {
        let mut data = b"SNSS".to_vec();
        data.extend(1i32.to_le_bytes());
        navigation(&mut data, 10, 0, "https://orphan.test");
        navigation(&mut data, 11, 0, "https://closed.test");
        command(&mut data, 16, &11i32.to_le_bytes());
        // A later surviving navigation record cannot resurrect a closed tab.
        navigation(&mut data, 11, 1, "https://also-closed.test");
        let mut payload = 1i32.to_le_bytes().to_vec();
        payload.extend(12i32.to_le_bytes());
        command(&mut data, 0, &payload);
        navigation(&mut data, 12, 0, "https://strict.test");
        let mut rows = Vec::new();
        chromium_session(&data, &mut rows).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text("URL"), "https://strict.test");
        assert!(!rows[0].is_partial_match());
        assert_eq!(rows[1].text("URL"), "https://orphan.test");
        assert!(rows[1].is_partial_match());
    }
    #[test]
    fn epochs_are_converted_without_local_timezone() {
        assert_eq!(
            timestamp(11_644_473_600_000_000, true),
            "1970-01-01T00:00:00+00:00"
        );
        assert_eq!(timestamp(1_000_000, false), "1970-01-01T00:00:01+00:00");
    }

    fn command(data: &mut Vec<u8>, id: u8, payload: &[u8]) {
        data.extend_from_slice(&((payload.len() + 1) as u16).to_le_bytes());
        data.push(id);
        data.extend_from_slice(payload);
    }

    fn navigation(data: &mut Vec<u8>, tab: i32, index: i32, address: &str) {
        let mut payload = vec![0; 4];
        payload.extend_from_slice(&tab.to_le_bytes());
        payload.extend_from_slice(&index.to_le_bytes());
        payload.extend_from_slice(&(address.len() as i32).to_le_bytes());
        payload.extend_from_slice(address.as_bytes());
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
        let title: Vec<_> = "A title".encode_utf16().collect();
        payload.extend_from_slice(&(title.len() as i32).to_le_bytes());
        payload.extend(title.into_iter().flat_map(u16::to_le_bytes));
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
        let size = payload.len() as u32 - 4;
        payload[..4].copy_from_slice(&size.to_le_bytes());
        command(data, 6, &payload);
    }

    #[test]
    fn chromium_replays_selected_navigation_and_removes_closed_tabs_and_windows() {
        let mut data = b"SNSS".to_vec();
        data.extend_from_slice(&1i32.to_le_bytes());
        for (window, tab) in [(1i32, 10i32), (1, 11), (2, 12)] {
            let mut payload = window.to_le_bytes().to_vec();
            payload.extend_from_slice(&tab.to_le_bytes());
            command(&mut data, 0, &payload);
            navigation(&mut data, tab, 0, "https://current.test");
            navigation(&mut data, tab, 1, "https://forward.test");
            let mut payload = tab.to_le_bytes().to_vec();
            payload.extend_from_slice(&0i32.to_le_bytes());
            command(&mut data, 7, &payload);
        }
        command(&mut data, 16, &11i32.to_le_bytes());
        command(&mut data, 17, &2i32.to_le_bytes());
        let mut rows = vec![];
        chromium_session(&data, &mut rows).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text("URL"), "https://current.test");
        assert_eq!(rows[0].fields["Observation"]["Tab"], 10);
        data.push(1);
        let mut partial = vec![];
        assert!(
            chromium_session(&data, &mut partial)
                .unwrap_err()
                .contains("truncated")
        );
        assert_eq!(partial.len(), 1);
        data[4..8].copy_from_slice(&5i32.to_le_bytes());
        assert!(
            chromium_session(&data, &mut vec![])
                .unwrap_err()
                .contains("encrypted")
        );
    }
}
