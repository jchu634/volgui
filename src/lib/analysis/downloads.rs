//! Download origins, execution candidates and observed connections, with separate provenance.
mod memory;
#[cfg(test)]
mod tests;

use super::{record, table};
use crate::{
    case::{CaseSnapshot, Run},
    results::{Query, ResultStore, StoredRecord},
    volatility::{Record, Table},
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub const PENDING: &str = "Waiting to recover download evidence after inventories";
pub const HELP: &str = "Recover download URLs and local filenames from NTFS Zone.Identifier and cached Chromium download history, then find matching executions and remote sockets. Collects available process lists, process scan, hidden-process cross-check, command lines, DLL paths, FileScan, ADS, NetScan and NetStat automatically. Recovers browser profile files when DumpFiles is available. Also scans acquisition bytes for residual process candidates, validating the supported Windows x64 layout against collected processes first. Filename matches, residual bytes and PID-only socket matches retain their limits and sources. Ports alone never establish a reverse shell. No custom arguments.";
pub const SOURCES: &[&str] = &[
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.cmdline.CmdLine",
    "windows.dlllist.DllList",
    "windows.malware.psxview.PsXView",
    "windows.filescan.FileScan",
    "windows.mftscan.ADS",
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
];
const MAX_ROWS: usize = 10_000;
const VERSION: &str = "downloads-v2";

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Download investigation cancelled".into())
    } else {
        Ok(())
    }
}

pub(super) fn filename(path: &str) -> &str {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
}

fn web_url(text: &str) -> Option<String> {
    let parsed = url::Url::parse(text.trim()).ok()?;
    (matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some())
        .then(|| text.trim().to_string())
}

fn decoded_filename(address: &str) -> Option<String> {
    let url = url::Url::parse(address).ok()?;
    let encoded = url.path_segments()?.next_back()?;
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < encoded.len() {
        if encoded.as_bytes()[i] == b'%'
            && i + 2 < encoded.len()
            && let Ok(b) = u8::from_str_radix(&encoded[i + 1..i + 3], 16)
        {
            bytes.push(b);
            i += 3;
        } else {
            bytes.push(encoded.as_bytes()[i]);
            i += 1;
        }
    }
    let name = String::from_utf8(bytes).ok()?;
    (!name.is_empty() && !name.contains(['/', '\\'])).then_some(name)
}

fn executable_url(address: &str) -> Option<String> {
    let name = decoded_filename(address)?;
    let lower = name.to_ascii_lowercase();
    [".exe", ".exe.bin", ".msi", ".scr", ".com", ".bat", ".ps1"]
        .iter()
        .any(|extension| lower.ends_with(extension))
        .then_some(name)
}

/// The stream's filename, not the URL suffix, identifies a renamed local download.
pub fn zone_origin(row: &Record) -> Option<Record> {
    let stream = ["ADS Filename", "Stream Name", "StreamName"]
        .iter()
        .map(|key| row.text(key))
        .find(|s| !s.is_empty())?;
    if !stream.eq_ignore_ascii_case("Zone.Identifier") {
        return None;
    }
    let mut text = row.text("Content");
    if text.is_empty() {
        let hex = row.text("Hexdump");
        let bytes = hex
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 16))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        text = String::from_utf8(bytes).ok()?;
    }
    let mut values = BTreeMap::new();
    let mut zone = false;
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.starts_with('[') {
            zone = line.eq_ignore_ascii_case("[ZoneTransfer]");
            continue;
        }
        if zone && let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let address = values.get("hosturl").and_then(|s| web_url(s))?;
    let name = ["Filename", "FileName", "Name"]
        .iter()
        .map(|key| row.text(key))
        .find(|s| !s.is_empty())?;
    let referrer = values
        .get("referrerurl")
        .and_then(|s| web_url(s))
        .unwrap_or_default();
    Some(record(
        json!({"Kind":"Download origin", "Filename":filename(&name),
        "Path": if name.contains(['/', '\\']) { &name } else { "" },
        "URL":address, "Website URL":if referrer.is_empty() { &address } else { &referrer },
        "Referrer URL":referrer, "Zone ID":values.get("zoneid"),
        "Download evidence":"NTFS Zone.Identifier", "Origin record":row.fields,
        "Interpretation":"The resident stream associates this local filename with HostUrl. It does not establish execution or maliciousness."}),
    ))
}

/// Read modern and older Chromium schemas without requiring optional columns.
pub(super) fn chromium_downloads(
    db: &Connection,
    rows: &mut Vec<Record>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut metadata = db
        .prepare("PRAGMA table_info(downloads)")
        .map_err(|e| e.to_string())?;
    let columns = metadata
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|e| e.to_string())?;
    if !columns.contains("id") {
        return Ok(());
    }
    let field = |name: &str| {
        if columns.contains(name) {
            format!("\"{name}\"")
        } else {
            "NULL".into()
        }
    };
    let fields = [
        "id",
        "target_path",
        "current_path",
        "full_path",
        "url",
        "tab_url",
        "referrer",
        "tab_referrer_url",
        "start_time",
        "end_time",
        "state",
        "opened",
    ];
    let sql = format!(
        "SELECT {} FROM downloads LIMIT 100000",
        fields
            .iter()
            .map(|name| field(name))
            .collect::<Vec<_>>()
            .join(",")
    );
    let has_chains = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='downloads_url_chains')", [], |r| r.get::<_, bool>(0)).unwrap_or(false);
    let mut chains = if has_chains {
        Some(db.prepare("SELECT chain_index,url FROM downloads_url_chains WHERE id=?1 ORDER BY chain_index LIMIT 128").map_err(|e| e.to_string())?)
    } else {
        None
    };
    let mut statement = db.prepare(&sql).map_err(|e| e.to_string())?;
    let mut result = statement.query([]).map_err(|e| e.to_string())?;
    while rows.len() < super::browser::MAX_ROWS {
        cancelled(cancel)?;
        let Some(row) = result
            .next()
            .map_err(|e| format!("Partial download history: {e}"))?
        else {
            break;
        };
        let id: i64 = row.get(0).map_err(|e| e.to_string())?;
        let text = |i| {
            row.get::<_, Option<String>>(i)
                .ok()
                .flatten()
                .unwrap_or_default()
        };
        let path = [text(1), text(2), text(3)]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_default();
        let chain = if let Some(statement) = &mut chains {
            statement
                .query_map([id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        let address = chain
            .last()
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| text(4));
        if path.is_empty() && web_url(&address).is_none() {
            continue;
        }
        let site = web_url(&text(5))
            .or_else(|| web_url(&text(6)))
            .or_else(|| web_url(&text(7)))
            .unwrap_or_default();
        let start = row.get::<_, Option<i64>>(8).ok().flatten();
        let end = row.get::<_, Option<i64>>(9).ok().flatten();
        // Pre-url-chain Chromium schemas store Unix seconds; modern ones use Chromium microseconds.
        let time = |t: i64| {
            if columns.contains("full_path") && !columns.contains("target_path") {
                chrono::DateTime::from_timestamp(t, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default()
            } else {
                super::browser::timestamp(t, true)
            }
        };
        rows.push(record(json!({"Kind":"Download", "Browser":"Chromium", "Download ID":id,
            "Filename":filename(&path), "Path":path, "URL":address, "Website URL":site,
            "Referrer URL":text(6), "Tab referrer URL":text(7), "URL chain":chain,
            "Time (UTC)":start.filter(|t| *t>0).map(time), "End time (UTC)":end.filter(|t| *t>0).map(time),
            "Download state":row.get::<_, Option<i64>>(10).ok().flatten(),
            "Opened":row.get::<_, Option<i64>>(11).ok().flatten(),
            "Download evidence":"Chromium downloads table", "Observation":{"Table":"downloads","ID":id},
            "Interpretation":"Recorded download target; opened is a browser flag, not an operating-system execution record."})));
    }
    Ok(())
}

fn provenance(source: &StoredRecord, plugin: &str, role: &str) -> Value {
    json!({"Role":role,"Run":source.run_id,"Row":source.row,"Record":source.id,"Plugin":plugin})
}

fn profile_provenance(row: &Record) -> Value {
    json!({"Role":"Download", "Run":row.text("Source run"), "File":row.text("Source file"),
        "Download ID":row.fields.get("Download ID"), "Observation":row.fields.get("Observation")})
}

#[derive(Clone)]
struct Process {
    pid: u64,
    name: String,
    path: String,
    birth: String,
    exit: String,
    source: Value,
    residual: bool,
}

fn number(row: &Record, key: &str) -> Option<u64> {
    super::process_memory::number(row, key)
}
fn first(row: &Record, fields: &[&str]) -> String {
    fields
        .iter()
        .map(|key| row.text(key))
        .find(|s| !s.is_empty() && s != "N/A")
        .unwrap_or_default()
}

fn command_executable(command: &str) -> String {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").into()
    } else {
        command.split_whitespace().next().unwrap_or("").into()
    }
}

fn time(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

fn socket_for(process: &Process, row: &Record) -> bool {
    if number(row, "PID") != Some(process.pid) {
        return false;
    }
    let created = first(row, &["Created", "CreateTime"]);
    match (time(&created), time(&process.birth), time(&process.exit)) {
        (Some(created), birth, exit) => {
            birth.is_none_or(|birth| created >= birth) && exit.is_none_or(|exit| created <= exit)
        }
        _ => true,
    }
}

pub fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    let evidence = document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Missing evidence")?;
    // Never allow later results, filtered inventories or another capture to become inputs.
    let mut preceding = document.clone();
    if let Some(index) = preceding.runs.iter().position(|r| r.id == run.id) {
        preceding.runs.truncate(index);
    }
    let mut seen = BTreeSet::new();
    let sources: Vec<_> = preceding
        .runs
        .iter()
        .rev()
        .filter(|r| {
            r.evidence_id == run.evidence_id
                && r.status.has_results()
                && r.arguments.is_empty()
                && (SOURCES.contains(&r.plugin.as_str()) || r.plugin == super::BROWSER)
                && seen.insert(r.plugin.clone())
        })
        .collect();
    let missing = SOURCES
        .iter()
        .filter(|plugin| !sources.iter().any(|r| r.plugin == **plugin))
        .copied()
        .collect::<Vec<_>>();
    let store = ResultStore::at(directory);
    let mut records = Vec::new();
    for source in &sources {
        // Profile recovery reads FileScan separately; it has no execution facts to join here.
        if source.plugin == "windows.filescan.FileScan" {
            continue;
        }
        let ids = store
            .query(&Query {
                runs: vec![source.id.clone()],
                ..Default::default()
            })?
            .ids;
        for ids in ids.chunks(256) {
            cancelled(cancel)?;
            for row in store.fetch(ids)? {
                records.push((source.plugin.as_str(), row));
            }
        }
    }
    let (profiles, profile_message) =
        super::browser::analyze_profiles(directory, &preceding, run, cancel, progress)?;
    let mut warnings = profiles.warnings.clone();
    for source in &sources {
        if source.status == crate::case::RunStatus::Warning {
            warnings.push(format!(
                "Source {} has incomplete coverage: {}",
                source.id, source.message
            ));
        }
    }
    if !missing.is_empty() {
        warnings.push(format!(
            "Missing source inventories: {}. Collect these inventories to complete coverage.",
            missing.join(", ")
        ));
    }
    let mut downloads: Vec<(Record, Value)> = Vec::new();
    let mut processes = Vec::new();
    let mut sockets = Vec::new();
    let mut commands = BTreeMap::<u64, Vec<(String, Value)>>::new();
    let mut paths = BTreeMap::<u64, BTreeSet<String>>::new();
    for (plugin, source) in &records {
        let row = &source.record;
        if *plugin == "windows.mftscan.ADS" {
            if let Some(origin) = zone_origin(row) {
                downloads.push((origin, provenance(source, plugin, "Download")));
            }
        } else if *plugin == super::BROWSER {
            if row.text("Kind") == "Download" {
                downloads.push((row.clone(), provenance(source, plugin, "Download")));
            } else if let Some(name) = executable_url(&row.text("URL")) {
                let mut lead = row.clone();
                lead.fields.insert("Filename".into(), name.into());
                lead.fields.insert(
                    "Download evidence".into(),
                    "Executable URL lead; download not established".into(),
                );
                // Browser ownership is not payload execution ownership.
                lead.fields.remove("PID");
                downloads.push((lead, provenance(source, plugin, "Browser URL lead")));
            }
        } else if plugin.ends_with("netscan.NetScan") || plugin.ends_with("netstat.NetStat") {
            sockets.push((row.clone(), provenance(source, plugin, "Socket")));
        } else if let Some(pid) = number(row, "PID").filter(|pid| *pid > 0) {
            if plugin.ends_with("cmdline.CmdLine") {
                let command = first(row, &["Args", "CommandLine"]);
                if !command.is_empty() {
                    commands
                        .entry(pid)
                        .or_default()
                        .push((command, provenance(source, plugin, "Command line")));
                }
            } else if plugin.ends_with("dlllist.DllList") {
                let path = row.text("Path");
                if path.to_ascii_lowercase().ends_with(".exe") {
                    paths.entry(pid).or_default().insert(path);
                }
            } else if plugin.ends_with("pslist.PsList")
                || plugin.ends_with("psscan.PsScan")
                || plugin.ends_with("psxview.PsXView")
            {
                processes.push(Process {
                    pid,
                    name: first(row, &["ImageFileName", "Name", "Process"]),
                    path: first(row, &["Path", "ImagePath"]),
                    birth: first(row, &["CreateTime"]),
                    exit: first(row, &["ExitTime", "Exit Time"]),
                    source: provenance(source, plugin, "Process"),
                    residual: false,
                });
            }
        }
    }
    for row in profiles
        .rows
        .into_iter()
        .filter(|r| r.text("Kind") == "Download")
    {
        let source = profile_provenance(&row);
        downloads.push((row, source));
    }
    // Keep distinct origin records and URL variants; repeated parsing of the same file need not duplicate them.
    let mut unique = BTreeSet::new();
    downloads.retain(|(row, source)| {
        unique.insert((
            row.text("Filename"),
            row.text("Path"),
            row.text("URL"),
            source.to_string(),
        ))
    });
    let anchors = processes
        .iter()
        .map(|p| (p.pid, p.name.clone(), p.birth.clone()))
        .collect::<Vec<_>>();
    let names = downloads
        .iter()
        .map(|(r, _)| r.text("Filename"))
        .filter(|s| !s.is_empty())
        .collect::<BTreeSet<_>>();
    let (residual, memory_message, memory_limited) =
        memory::scan(&evidence.path, &names, &anchors, cancel, progress)?;
    if memory_limited {
        warnings.push("Residual process scan reached a filename or finding limit. Narrow the inputs to complete coverage.".into());
    }
    for row in residual {
        processes.push(Process { pid:number(&row,"PID").unwrap(),name:row.text("Process"),path:String::new(),
            birth:row.text("CreateTime"),exit:row.text("ExitTime"),source:json!({"Role":"Residual process","Offset":row.fields["Acquisition offset"],"Match offset":row.fields["Match offset"],"Profile":row.text("Profile"),"Reference PIDs":row.fields["Profile reference PIDs"],"Inventory runs":sources.iter().filter(|r| r.plugin.ends_with("pslist.PsList") || r.plugin.ends_with("psscan.PsScan")).map(|r| &r.id).collect::<Vec<_>>()}),residual:true });
    }
    // Prefer the complete inventory identity over duplicate PsScan/cross-check or carved copies.
    let known = processes
        .iter()
        .filter(|p| !p.birth.is_empty())
        .map(|p| (p.pid, p.name.to_ascii_lowercase()))
        .collect::<BTreeSet<_>>();
    processes
        .retain(|p| !p.birth.is_empty() || !known.contains(&(p.pid, p.name.to_ascii_lowercase())));
    let mut identities = BTreeSet::new();
    processes.sort_by_key(|p| p.residual);
    processes.retain(|p| identities.insert((p.pid, p.name.to_ascii_lowercase(), p.birth.clone())));
    let mut lifetimes = BTreeMap::<u64, BTreeSet<String>>::new();
    for p in &processes {
        lifetimes.entry(p.pid).or_default().insert(p.birth.clone());
    }
    let mut rows = Vec::new();
    for (download, origin) in downloads {
        cancelled(cancel)?;
        let name = download.text("Filename");
        let mut matches = Vec::new();
        for process in &processes {
            if name.is_empty() {
                continue;
            }
            let unique_pid = lifetimes
                .get(&process.pid)
                .is_some_and(|times| times.len() == 1)
                && !process.residual;
            let mut candidates = if unique_pid {
                paths.get(&process.pid).cloned().unwrap_or_default()
            } else {
                BTreeSet::new()
            };
            if !process.path.is_empty() {
                candidates.insert(process.path.clone());
            }
            if unique_pid && let Some(commands) = commands.get(&process.pid) {
                for (cmd, _) in commands {
                    candidates.insert(command_executable(cmd));
                }
            }
            if process.name.eq_ignore_ascii_case(&name)
                || candidates
                    .iter()
                    .any(|path| filename(path).eq_ignore_ascii_case(&name))
            {
                matches.push((process, candidates));
            }
        }
        if matches.is_empty() {
            let mut row = download_row(&download, &origin);
            row.fields.insert(
                "Finding".into(),
                "Download origin; execution not recovered".into(),
            );
            rows.push(row);
        }
        for (process, candidates) in matches {
            let mut row = download_row(&download, &origin);
            row.fields.insert("PID".into(), process.pid.into());
            row.fields
                .insert("Process".into(), process.name.clone().into());
            row.fields
                .insert("CreateTime".into(), process.birth.clone().into());
            row.fields
                .insert("ExitTime".into(), process.exit.clone().into());
            row.fields.insert(
                "Execution evidence".into(),
                if process.residual {
                    "Residual process candidate; activity at acquisition unknown"
                } else {
                    "Collected process inventory"
                }
                .into(),
            );
            let path = download.text("Path");
            let exact = !path.is_empty()
                && candidates.iter().any(|p| {
                    p.replace('/', "\\")
                        .eq_ignore_ascii_case(&path.replace('/', "\\"))
                });
            row.fields.insert(
                "Match basis".into(),
                if exact {
                    "Exact path, ignoring Windows case"
                } else {
                    "Filename only; verify path and possible renames"
                }
                .into(),
            );
            row.fields
                .insert("Executable paths".into(), json!(candidates));
            let mut proof = vec![origin.clone(), process.source.clone()];
            if !process.residual
                && lifetimes
                    .get(&process.pid)
                    .is_some_and(|times| times.len() == 1)
                && let Some(cmds) = commands.get(&process.pid)
            {
                row.fields.insert(
                    "Command lines".into(),
                    json!(cmds.iter().map(|(cmd, _)| cmd).collect::<Vec<_>>()),
                );
                proof.extend(cmds.iter().map(|(_, source)| source.clone()));
            }
            if let Some(offset) = process.source.get("Offset") {
                row.fields
                    .insert("Acquisition offset".into(), offset.clone());
            }
            // Multiple lifetimes with the same PID require a socket timestamp to disambiguate.
            let ambiguous = lifetimes
                .get(&process.pid)
                .is_some_and(|times| times.len() > 1);
            let peers = sockets
                .iter()
                .filter(|(socket, _)| {
                    socket_for(process, socket)
                        && (!ambiguous
                            || time(&first(socket, &["Created", "CreateTime"])).is_some())
                })
                .filter_map(|(socket, source)| {
                    let ip = first(socket, &["ForeignAddr", "RemoteAddr", "RemoteAddress"]);
                    let ip = ip
                        .parse::<IpAddr>()
                        .ok()
                        .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())?;
                    let port = number(socket, "ForeignPort")
                        .or_else(|| number(socket, "RemotePort"))?
                        .try_into()
                        .ok()
                        .filter(|port: &u16| *port > 0)?;
                    Some((socket, source, ip, port))
                })
                .collect::<Vec<_>>();
            if peers.is_empty() {
                row.fields.insert(
                    "Finding".into(),
                    "Download + process candidate; endpoint not recovered".into(),
                );
                row.fields.insert(
                    "Network evidence".into(),
                    if ambiguous {
                        "PID has multiple lifetimes; sockets without timestamps were not joined"
                    } else {
                        "No owned remote socket recovered; unowned sockets remain in Network"
                    }
                    .into(),
                );
                row.fields.insert("Sources".into(), json!(proof));
                rows.push(row);
            } else {
                for (socket, source, ip, port) in peers {
                    let mut joined = row.clone();
                    let mut sources = proof.clone();
                    sources.push(source.clone());
                    joined.fields.insert(
                        "Finding".into(),
                        "Download + process candidate + socket".into(),
                    );
                    joined
                        .fields
                        .insert("Remote IP".into(), ip.to_string().into());
                    joined.fields.insert("Remote port".into(), port.into());
                    joined
                        .fields
                        .insert("State".into(), socket.text("State").into());
                    let timestamp = first(socket, &["Created", "CreateTime"]);
                    joined.fields.insert("Network evidence".into(),if time(&timestamp).is_none() {
                        "PID-only socket match; socket timestamp unavailable, so lifetime overlap is not established. Verify payload behavior before calling it a reverse shell."
                    } else if time(&process.birth).is_none() {
                        "PID-only socket match; process creation time unavailable, so lifetime overlap is not established. Verify payload behavior before calling it a reverse shell."
                    } else {
                        "Socket PID and creation time match the process lifetime; verify payload behavior before calling it a reverse shell."
                    }.into());
                    joined
                        .fields
                        .insert("Socket record".into(), json!(socket.fields));
                    joined.fields.insert("Sources".into(), json!(sources));
                    rows.push(joined);
                    if rows.len() >= MAX_ROWS {
                        break;
                    }
                }
            }
            if rows.len() >= MAX_ROWS {
                break;
            }
        }
        if rows.len() >= MAX_ROWS {
            break;
        }
    }
    rows.sort_by_key(|row| (row.text("PID").is_empty(), row.text("Filename")));
    let limited = rows.len() >= MAX_ROWS;
    rows.truncate(MAX_ROWS);
    let unowned = sockets
        .iter()
        .filter(|(r, _)| number(r, "PID").is_none())
        .count();
    let coverage = format!(
        "Source inventories unavailable or not successfully collected without filters: {}. {unowned} sockets have no PID and cannot be attributed. {memory_message} {profile_message}",
        if missing.is_empty() {
            "none".into()
        } else {
            missing.join(", ")
        }
    );
    for row in &mut rows {
        row.fields.insert("Parser version".into(), VERSION.into());
        row.fields
            .insert("Evidence SHA-256".into(), evidence.sha256.clone().into());
    }
    // Coverage is a visible result even when recovery finds nothing.
    rows.push(record(
        json!({"Finding":"Analysis coverage", "Interpretation":coverage, "Limit reached":limited,
        "Evidence SHA-256":evidence.sha256,"Parser version":VERSION}),
    ));
    let message = format!(
        "{} investigation findings. {}{coverage}",
        rows.len() - 1,
        if limited {
            "Finding limit reached. "
        } else {
            ""
        }
    );
    if limited {
        warnings.push(
            "Finding limit reached. Narrow the source inventories to complete coverage.".into(),
        );
    }
    Ok((table(rows).with_warnings(warnings), message))
}

fn download_row(download: &Record, origin: &Value) -> Record {
    let mut row = download.clone();
    row.fields.remove("PID");
    row.fields.insert(
        "Download evidence".into(),
        download
            .fields
            .get("Download evidence")
            .cloned()
            .unwrap_or_else(|| "Recorded browser download".into()),
    );
    if let Some(run) = origin.get("Run") {
        row.fields.insert("Source run".into(), run.clone());
    }
    row.fields.insert("Sources".into(), json!([origin]));
    row
}
