//! Recover text candidates from application-private memory, including unsaved edits.
//!
//! These are carved strings, not a version-specific reconstruction of editor tabs.
use super::{
    APPLICATION, prepare,
    process_memory::{DumpScope, Region, number, regions},
    record,
};
use crate::{
    artifacts::OperatingSystem,
    case::{CaseSnapshot, Evidence, Run},
    results::{Query, ResultStore},
    volatility::{Installation, Record, Table},
};
use serde_json::json;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const MEMMAP: &str = "windows.memmap.Memmap";
pub const VADINFO: &str = "windows.vadinfo.VadInfo";
pub const INVENTORY: [&str; 2] = ["windows.pslist.PsList", "windows.cmdline.CmdLine"];
pub const HELP: &str = "Recover text from a chosen process ID, including old edits and unsaved text. Prerequisites and dumps are collected automatically.\n\nOptions:\n  --pid <PID>       Choose the process to scan (required).\n  --contains <text> Retain text containing this literal string, ignoring ASCII case.\n\nText candidates can include old edits, resources and partial buffers. File paths in the same process do not establish which document owns a text candidate. Tab state, save state and current buffer order are unknown. UTF-8 and UTF-16 text, addresses and dump offsets are retained. Text must contain at least eight characters, four ASCII letters or digits, and at least half ASCII characters. Text entirely in other scripts may be omitted.";
const CHUNK: usize = 1024 * 1024;
const MAX_TEXT: usize = 64 * 1024;
const MAX_ROWS: usize = 50_000;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROCESSES: usize = 64;

#[derive(Default)]
struct Options {
    pid: Option<u64>,
    contains: Option<String>,
    inventory: Vec<String>,
    sources: Vec<String>,
}

fn options(arguments: &[String]) -> Result<Options, String> {
    let mut result = Options::default();
    let mut args = arguments.iter();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("Missing value for {flag}"))?;
        match flag.as_str() {
            "--pid" if result.pid.is_none() => {
                result.pid = Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("--pid requires a positive process ID")?,
                );
            }
            "--contains" if result.contains.is_none() && !value.is_empty() => {
                result.contains = Some(value.to_ascii_lowercase());
            }
            "--inventory-run" => result.inventory.push(value.clone()),
            "--source-run" => result.sources.push(value.clone()),
            _ => return Err(format!("Unknown or repeated application option: {flag}")),
        }
    }
    Ok(result)
}

pub fn validate(arguments: &[String]) -> Result<(), String> {
    options(arguments).map(|_| ())
}

pub fn target_pid(arguments: &[String]) -> Result<u64, String> {
    options(arguments)?
        .pid
        .ok_or_else(|| "Choose a PID to scan application memory".into())
}

/// Open the dump pinned to a saved scan, including full and user-memory dumps.
pub fn dump_path(directory: &Path, document: &CaseSnapshot, run: &Run) -> Option<PathBuf> {
    if run.plugin != APPLICATION || !run.status.has_results() {
        return None;
    }
    let opts = options(&run.arguments).ok()?;
    let pid = opts.pid?;
    let dump = opts.sources.iter().find_map(|id| {
        let dump = source(document, id, &run.evidence_id).ok()?;
        (dump.plugin == MEMMAP && DumpScope::from_arguments(&dump.arguments, pid).is_some())
            .then_some(dump)
    })?;
    let path = directory
        .join("analyses")
        .join(&dump.id)
        .join(format!("pid.{pid}.dmp"));
    crate::object_store::exists(&path).then_some(path)
}

/// User options survive retries; resolved source IDs must be selected again.
pub fn user_arguments(arguments: &[String]) -> Result<Vec<String>, String> {
    validate(arguments)?;
    Ok(arguments
        .chunks_exact(2)
        .filter(|pair| matches!(pair[0].as_str(), "--pid" | "--contains"))
        .flatten()
        .cloned()
        .collect())
}

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Application analysis cancelled".into())
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct Process {
    name: String,
    command: String,
}

fn processes(
    directory: &Path,
    inventory: &[String],
    options: &Options,
    cancel: &AtomicBool,
) -> Result<BTreeMap<u64, Process>, String> {
    let store = ResultStore::at(directory);
    let mut result: BTreeMap<u64, Process> = BTreeMap::new();
    // Inventory order is PsList followed by CmdLine. Names come from PsList only.
    for (index, source) in inventory.iter().enumerate() {
        let ids = store
            .query(&Query {
                runs: vec![source.clone()],
                ..Default::default()
            })?
            .ids;
        for chunk in ids.chunks(256) {
            cancelled(cancel)?;
            for stored in store.fetch(chunk)? {
                let row = stored.record;
                let Some(pid) = number(&row, "PID") else {
                    continue;
                };
                if index == 0 {
                    let name = row.text("ImageFileName");
                    if options.pid.map_or_else(
                        || name.eq_ignore_ascii_case("notepad.exe"),
                        |wanted| wanted == pid,
                    ) {
                        result.insert(
                            pid,
                            Process {
                                name,
                                command: String::new(),
                            },
                        );
                        if result.len() > MAX_PROCESSES {
                            return Err(format!(
                                "More than {MAX_PROCESSES} application processes found. Use --pid to select one."
                            ));
                        }
                    }
                } else if let Some(process) = result.get_mut(&pid) {
                    process.command = row.text("Args");
                }
            }
        }
    }
    if options.pid.is_some() && result.is_empty() {
        return Err("The requested PID was not found in the collected process inventory".into());
    }
    Ok(result)
}

/// Resolve inventories once and pin exact dump and VAD run IDs in the native job.
pub fn recovery_runs(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &Evidence,
    engine: &Installation,
    arguments: &[String],
    cancel: &AtomicBool,
) -> Result<Vec<Run>, String> {
    if evidence.operating_system != OperatingSystem::Windows {
        return Err("Process Memory recovery currently requires Windows evidence".into());
    }
    let arguments = user_arguments(arguments)?;
    target_pid(&arguments)?;
    let opts = options(&arguments)?;
    let inventory: Vec<_> = INVENTORY
        .iter()
        .map(|plugin| {
            document
                .runs
                .iter()
                .rev()
                .find(|r| {
                    r.evidence_id == evidence.id && r.plugin == *plugin && r.arguments.is_empty()
                })
                .filter(|r| r.status.has_results())
                .map(|r| r.id.clone())
                .ok_or_else(|| {
                    format!("Application recovery requires a successful unfiltered {plugin} job")
                })
        })
        .collect::<Result<_, _>>()?;
    let processes = processes(directory, &inventory, &opts, cancel)?;
    let mut pinned = arguments;
    for id in &inventory {
        pinned.extend(["--inventory-run".into(), id.clone()]);
    }
    let mut runs = Vec::new();
    for pid in processes.keys() {
        for (plugin, args) in [
            (VADINFO, vec!["--pid".into(), pid.to_string()]),
            (
                MEMMAP,
                if engine.user_memory_dumps {
                    DumpScope::User
                } else {
                    DumpScope::Full
                }
                .arguments(*pid),
            ),
        ] {
            cancelled(cancel)?;
            let reusable = document.runs.iter().rev().find(|r| {
                r.evidence_id == evidence.id
                    && r.plugin == plugin
                    && (if plugin == MEMMAP {
                        DumpScope::from_arguments(&r.arguments, *pid).is_some()
                    } else {
                        r.arguments == args
                    })
                    && r.status.has_results()
                    && (plugin != MEMMAP
                        || crate::object_store::exists(
                            &directory
                                .join("analyses")
                                .join(&r.id)
                                .join(format!("pid.{pid}.dmp")),
                        ))
            });
            let id = if let Some(source) = reusable {
                source.id.clone()
            } else {
                let source = engine.prepare(evidence, plugin, args, &directory.join("analyses"))?;
                let id = source.id.clone();
                runs.push(source);
                id
            };
            pinned.extend(["--source-run".into(), id]);
        }
    }
    runs.push(prepare(evidence, APPLICATION, pinned)?);
    Ok(runs)
}

fn source<'a>(document: &'a CaseSnapshot, id: &str, evidence: &str) -> Result<&'a Run, String> {
    document
        .runs
        .iter()
        .find(|r| r.id == id && r.evidence_id == evidence && r.status.has_results())
        .ok_or_else(|| {
            format!(
                "Required application source {id} did not complete successfully for this evidence"
            )
        })
}

fn private_ranges(table: Table, pid: u64, mappings: Vec<Region>) -> Result<Vec<Region>, String> {
    let mut vads: Vec<_> = table
        .rows
        .iter()
        .filter(|r| {
            number(r, "PID") == Some(pid)
                && (number(r, "PrivateMemory") == Some(1)
                    || r.fields.get("PrivateMemory").and_then(|v| v.as_bool()) == Some(true))
                && matches!(
                    r.text("Protection").as_str(),
                    "PAGE_READWRITE"
                        | "PAGE_WRITECOPY"
                        | "PAGE_EXECUTE_READWRITE"
                        | "PAGE_EXECUTE_WRITECOPY"
                )
        })
        .filter_map(|r| {
            Some((
                number(r, "Start VPN")?,
                number(r, "End VPN")?.checked_add(1)?,
            ))
        })
        .collect();
    vads.sort_unstable();
    if vads.windows(2).any(|v| v[0].1 > v[1].0) {
        return Err(
            "Overlapping private memory regions; cannot determine safe scan coverage".into(),
        );
    }
    let mut result = Vec::new();
    for region in mappings {
        let end = region.virtual_start + region.length;
        for &(start, stop) in &vads[vads.partition_point(|v| v.1 <= region.virtual_start)..] {
            if start >= end {
                break;
            }
            let first = region.virtual_start.max(start);
            let last = end.min(stop);
            if first < last {
                result.push(Region {
                    file: region.file + first - region.virtual_start,
                    virtual_start: first,
                    length: last - first,
                });
            }
        }
    }
    Ok(result)
}

fn metadata_table(directory: &Path, source: &Run, cancel: &AtomicBool) -> Result<Table, String> {
    let store = ResultStore::at(directory);
    let index = store.query(&Query {
        runs: vec![source.id.clone()],
        ..Default::default()
    })?;
    if index.ids.len() > 1_000_000 {
        return Err("Process has more than 1,000,000 mapping records; recovery refused".into());
    }
    let mut rows = Vec::new();
    for ids in index.ids.chunks(256) {
        cancelled(cancel)?;
        for mut stored in store.fetch(ids)? {
            stored.record.fields.retain(|key, _| {
                matches!(
                    key.as_str(),
                    "File output"
                        | "User address limit"
                        | "Offset in File"
                        | "Virtual"
                        | "Size"
                        | "PID"
                        | "PrivateMemory"
                        | "Protection"
                        | "Start VPN"
                        | "End VPN"
                )
            });
            rows.push(stored.record);
        }
    }
    Ok(Table {
        warnings: Vec::new(),
        columns: Vec::new(),
        rows,
    })
}

struct Fragment {
    text: String,
    encoding: &'static str,
    offset: u64,
    address: u64,
    length: usize,
    boundary: &'static str,
}

#[derive(Default)]
struct Lane {
    bytes: Vec<u8>,
    start: u64,
    continuation: bool,
}

impl Lane {
    fn finish(
        &mut self,
        encoding: &'static str,
        boundary: &'static str,
        emit: &mut impl FnMut(Fragment),
    ) {
        if self.bytes.is_empty() {
            return;
        }
        let text = if encoding == "UTF-8" {
            String::from_utf8(self.bytes.clone()).ok()
        } else {
            let units: Vec<_> = self
                .bytes
                .chunks_exact(2)
                .map(|b| {
                    if encoding == "UTF-16LE" {
                        u16::from_le_bytes([b[0], b[1]])
                    } else {
                        u16::from_be_bytes([b[0], b[1]])
                    }
                })
                .collect();
            String::from_utf16(&units).ok()
        };
        if let Some(text) = text.filter(|s| {
            let count = s.chars().count();
            // ASCII anchors reject swapped UTF-16 and arbitrary heap words.
            count >= 8
                && s.chars().filter(char::is_ascii_alphanumeric).count() >= 4
                && s.chars().filter(char::is_ascii).count() * 2 >= count
        }) {
            emit(Fragment {
                text,
                encoding,
                offset: self.start,
                address: 0,
                length: self.bytes.len(),
                boundary: if self.continuation {
                    "Continuation after length limit; may be partial"
                } else {
                    boundary
                },
            });
        }
        self.bytes.clear();
    }

    fn feed(
        &mut self,
        bytes: &[u8],
        allowed: bool,
        offset: u64,
        encoding: &'static str,
        emit: &mut impl FnMut(Fragment),
    ) {
        if !allowed {
            self.finish(encoding, "Delimiter found; may include adjacent text", emit);
            self.continuation = false;
            return;
        }
        if self.bytes.is_empty() {
            self.start = offset;
        }
        self.bytes.extend_from_slice(bytes);
        if self.bytes.len() >= MAX_TEXT {
            self.finish(encoding, "Length limit; may be truncated", emit);
            self.continuation = true;
        }
    }
}

fn printable(unit: u16) -> bool {
    matches!(unit, 9 | 10 | 13)
        || char::from_u32(u32::from(unit)).is_some_and(|c| {
            !c.is_control() && !matches!(unit, 0x7f..=0x9f | 0xe000..=0xf8ff | 0xfdd0..=0xffff)
        })
}

/// Keep shifted byte-order interpretations in details rather than duplicate rows.
fn coalesce_mirrors(
    rows: &mut Vec<Record>,
    seen: &BTreeMap<(String, &'static str), usize>,
    start: usize,
) -> usize {
    let mut remove = BTreeSet::new();
    for ((text, encoding), &little) in seen {
        if *encoding != "UTF-16LE" {
            continue;
        }
        let Some(&big) = seen.get(&(text.clone(), "UTF-16BE")) else {
            continue;
        };
        let a = &rows[little];
        let b = &rows[big];
        if number(a, "Dump offset")
            .zip(number(b, "Dump offset"))
            .is_none_or(|(a, b)| a.abs_diff(b) != 1)
            || a.fields["Byte length"] != b.fields["Byte length"]
        {
            continue;
        }
        let alternate = json!({"Encoding":"UTF-16BE", "Dump offset":b.fields["Dump offset"],
            "Virtual address":b.fields["Virtual address"], "Byte length":b.fields["Byte length"],
            "Occurrences":b.fields["Occurrences"], "Meaning":"Same text under a shifted byte-order interpretation; not a separate document"});
        rows[little]
            .fields
            .insert("Alternate interpretation".into(), alternate);
        remove.insert(big);
    }
    let mut removed_bytes = 0;
    let tail = rows.split_off(start);
    for (index, row) in tail.into_iter().enumerate() {
        if remove.contains(&(start + index)) {
            removed_bytes += row.text("Text").len();
        } else {
            rows.push(row);
        }
    }
    removed_bytes
}

#[derive(Default)]
struct Utf8Lane {
    lane: Lane,
    pending: Vec<u8>,
    start: u64,
    width: usize,
}

impl Utf8Lane {
    fn feed(&mut self, byte: u8, offset: u64, emit: &mut impl FnMut(Fragment)) {
        if !self.pending.is_empty() {
            if (0x80..=0xbf).contains(&byte) {
                self.pending.push(byte);
                if self.pending.len() == self.width {
                    let allowed = std::str::from_utf8(&self.pending)
                        .ok()
                        .and_then(|s| s.chars().next())
                        .is_some_and(|c| !c.is_control());
                    self.lane
                        .feed(&self.pending, allowed, self.start, "UTF-8", emit);
                    self.pending.clear();
                }
                return;
            }
            self.lane.feed(&[], false, self.start, "UTF-8", emit);
            self.pending.clear();
        }
        match byte {
            0xc2..=0xf4 => {
                self.start = offset;
                self.width = if byte < 0xe0 {
                    2
                } else if byte < 0xf0 {
                    3
                } else {
                    4
                };
                self.pending.push(byte);
            }
            _ => self.lane.feed(
                &[byte],
                byte.is_ascii_graphic() || matches!(byte, b' ' | 9 | 10 | 13),
                offset,
                "UTF-8",
                emit,
            ),
        }
    }
}

#[derive(Default)]
struct WideLane {
    lane: Lane,
    high: Option<([u8; 2], u64)>,
}

impl WideLane {
    fn feed(
        &mut self,
        pair: [u8; 2],
        offset: u64,
        encoding: &'static str,
        emit: &mut impl FnMut(Fragment),
    ) {
        let unit = if encoding == "UTF-16LE" {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        };
        if let Some((high, start)) = self.high.take() {
            if (0xdc00..=0xdfff).contains(&unit) {
                self.lane.feed(
                    &[high[0], high[1], pair[0], pair[1]],
                    true,
                    start,
                    encoding,
                    emit,
                );
                return;
            }
            self.lane.feed(&[], false, start, encoding, emit);
        }
        if (0xd800..=0xdbff).contains(&unit) {
            self.high = Some((pair, offset));
        } else {
            self.lane.feed(
                &pair,
                !(0xdc00..=0xdfff).contains(&unit) && printable(unit),
                offset,
                encoding,
                emit,
            );
        }
    }
}

fn scan(
    file: &mut (impl Read + Seek),
    regions: &[Region],
    cancel: &AtomicBool,
    mut emit: impl FnMut(Fragment) -> bool,
) -> Result<bool, String> {
    let mut buffer = vec![0; CHUNK];
    for region in regions {
        cancelled(cancel)?;
        file.seek(SeekFrom::Start(region.file))
            .map_err(|e| e.to_string())?;
        let mut utf8 = Utf8Lane::default();
        let mut lanes: [WideLane; 4] = std::array::from_fn(|_| WideLane::default());
        let mut previous = None;
        let mut consumed = 0;
        let stopped = Cell::new(false);
        let mut output = |mut fragment: Fragment| {
            fragment.address = region.virtual_start + fragment.offset - region.file;
            if !emit(fragment) {
                stopped.set(true);
            }
        };
        while consumed < region.length {
            cancelled(cancel)?;
            let size = (region.length - consumed).min(CHUNK as u64) as usize;
            file.read_exact(&mut buffer[..size])
                .map_err(|e| e.to_string())?;
            for (index, &byte) in buffer[..size].iter().enumerate() {
                let offset = region.file + consumed + index as u64;
                utf8.feed(byte, offset, &mut output);
                if let Some(first) = previous {
                    let pair = [first, byte];
                    let alignment = ((offset - region.file - 1) % 2) as usize;
                    lanes[alignment].feed(pair, offset - 1, "UTF-16LE", &mut output);
                    lanes[2 + alignment].feed(pair, offset - 1, "UTF-16BE", &mut output);
                }
                previous = Some(byte);
            }
            consumed += size as u64;
            // Bound retained findings even when a single chunk contains many strings.
            if stopped.get() {
                return Ok(true);
            }
        }
        utf8.lane
            .finish("UTF-8", "Mapping boundary; may be truncated", &mut output);
        for (index, lane) in lanes.iter_mut().enumerate() {
            lane.lane.finish(
                if index <= 1 { "UTF-16LE" } else { "UTF-16BE" },
                "Mapping boundary; may be truncated",
                &mut output,
            );
        }
        if stopped.get() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn kind(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if !text.contains(['\r', '\n'])
        && (text.contains(":\\") || text.starts_with("\\Device\\"))
        && [".txt", ".csv", ".log", ".md", ".json", ".xml", ".rtf"]
            .iter()
            .any(|ext| lower.ends_with(ext))
    {
        "Document path candidate"
    } else if text
        .split(['\r', '\n'])
        .filter(|line| line.chars().filter(|c| c.is_alphabetic()).count() >= 4)
        .count()
        >= 2
        || text.len() >= 80 && text.split_whitespace().count() >= 8
    {
        "Document text candidate"
    } else {
        "Memory text fragment"
    }
}

pub(super) fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    let opts = options(&run.arguments)?;
    if opts.inventory.len() != 2 {
        return Err("Queue Process Memory recovery from Choose analyses to collect and pin its sources first".into());
    }
    for (id, plugin) in opts.inventory.iter().zip(INVENTORY) {
        let r = source(document, id, &run.evidence_id)?;
        if r.plugin != plugin || !r.arguments.is_empty() {
            return Err("Invalid application process inventory".into());
        }
    }
    let processes = processes(directory, &opts.inventory, &opts, cancel)?;
    if processes.is_empty() {
        return Ok((
            super::table(Vec::new()),
            "No Notepad processes found in this capture. Use --pid to select another application."
                .into(),
        ));
    }
    let mut sources = BTreeMap::new();
    for id in &opts.sources {
        let r = source(document, id, &run.evidence_id)?;
        let pid = r
            .arguments
            .windows(2)
            .find(|p| p[0] == "--pid")
            .and_then(|p| p[1].parse::<u64>().ok())
            .ok_or("Application source has no PID")?;
        if !processes.contains_key(&pid) || !matches!(r.plugin.as_str(), MEMMAP | VADINFO) {
            return Err("Application source does not match the selected processes".into());
        }
        let expected = vec!["--pid".to_string(), pid.to_string()];
        if (r.plugin == MEMMAP && DumpScope::from_arguments(&r.arguments, pid).is_none())
            || (r.plugin == VADINFO && r.arguments != expected)
        {
            return Err("Application source has unexpected collection filters".into());
        }
        if sources.insert((pid, r.plugin.as_str()), r).is_some() {
            return Err("Duplicate application source".into());
        }
    }
    let mut rows: Vec<Record> = Vec::new();
    let mut bytes = 0;
    let mut warnings = Vec::new();
    let mut parsed = 0;
    let mut limited = false;
    for (pid, process) in processes {
        cancelled(cancel)?;
        let map = sources
            .get(&(pid, MEMMAP))
            .ok_or("Missing pinned process dump source")?;
        let vad = sources
            .get(&(pid, VADINFO))
            .ok_or("Missing pinned process region source")?;
        let path = directory
            .join("analyses")
            .join(&map.id)
            .join(format!("pid.{pid}.dmp"));
        progress(format!(
            "Recovering application text: {} PID {pid}",
            process.name
        ));
        let result = (|| {
            let mut file = crate::extracted_files::open_artifact(&path)?;
            let total = file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
            let (ranges, rejected) = regions(
                metadata_table(directory, map, cancel)?,
                &format!("pid.{pid}.dmp"),
                total,
                DumpScope::from_arguments(&map.arguments, pid)
                    .ok_or("Application dump has unexpected collection filters")?,
            )?;
            if rejected > 0 {
                warnings.push(format!(
                    "PID {pid}: skipped {rejected} invalid mapping ranges"
                ));
            }
            let ranges = private_ranges(metadata_table(directory, vad, cancel)?, pid, ranges)?;
            if ranges.is_empty() {
                return Err("No readable private writable memory regions".into());
            }
            let mut seen: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
            let start = rows.len();
            limited |= scan(&mut file, &ranges, cancel, |fragment| {
                if opts
                    .contains
                    .as_ref()
                    .is_some_and(|s| !fragment.text.to_ascii_lowercase().contains(s))
                {
                    return true;
                }
                let key = (fragment.text.clone(), fragment.encoding);
                if let Some(&index) = seen.get(&key) {
                    let row = &mut rows[index];
                    let count = row.fields["Occurrences"].as_u64().unwrap_or(1) + 1;
                    row.fields.insert("Occurrences".into(), json!(count));
                    return true;
                }
                if rows.len() >= MAX_ROWS || bytes + fragment.text.len() > MAX_BYTES {
                    return false;
                }
                bytes += fragment.text.len();
                seen.insert(key, rows.len());
                rows.push(record(json!({
                    "Application": if process.name.eq_ignore_ascii_case("notepad.exe") { "Notepad" } else { &process.name },
                    "PID":pid, "Process":process.name, "Command line":process.command,
                    "Kind":kind(&fragment.text), "Text":fragment.text, "Encoding":fragment.encoding,
                    "Virtual address":format!("{:#x}", fragment.address), "Dump offset":fragment.offset,
                    "Byte length":fragment.length, "String boundary":fragment.boundary, "Occurrences":1,
                    "Source run":map.id, "Region run":vad.id, "Inventory runs":opts.inventory,
                    "Source file":path.strip_prefix(directory).unwrap_or(&path).display().to_string(),
                    "Save state":"Unknown", "Document association":"Unknown",
                    "Observation":"Carved text in private writable process memory. May include old edits, resources, undo data or partial buffers. A path or command line in this process does not bind text to a file or establish current tab contents. Repeated exact strings within this source share one row; the first address is retained."
                })));
                true
            })?;
            bytes -= coalesce_mirrors(&mut rows, &seen, start);
            Ok::<_, String>(())
        })();
        match result {
            Ok(()) => parsed += 1,
            Err(error) => {
                cancelled(cancel)?;
                warnings.push(format!("PID {pid}: {error}"));
            }
        }
        if limited || rows.len() >= MAX_ROWS || bytes >= MAX_BYTES {
            break;
        }
    }
    rows.sort_by_key(|row| match row.text("Kind").as_str() {
        "Document text candidate" => 0,
        "Document path candidate" => 1,
        _ => 2,
    });
    let count = rows.len();
    let limited = limited || count >= MAX_ROWS || bytes >= MAX_BYTES;
    if limited {
        warnings.push("Stopped at the finding or text-byte limit; use --pid or --contains to narrow recovery. Rerunning the same request uses the same limits.".into());
    }
    Ok((
        super::table(rows).with_warnings(warnings.clone()),
        format!(
            "Recovered {count} text candidates from {parsed} application process dumps. Only private writable user mappings were scanned. Text fragments do not establish current document, tab order or save state. Exact duplicates retain their first source address.{}\n{}",
            if limited {
                " Stopped at the finding or text-byte limit; use --pid or --contains to narrow recovery."
            } else {
                ""
            },
            warnings.join("\n")
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn scans_encodings_chunk_boundaries_and_mapping_gaps_without_joining_them() {
        let mut bytes = vec![0; CHUNK - 5];
        let utf8 = bytes.len();
        bytes.extend_from_slice("Customer café has unsaved changes".as_bytes());
        bytes.extend_from_slice(&[0, 0, 0]);
        let wide = bytes.len();
        bytes.extend(
            "Customer list: Łukasz 😀\rOther customer"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend_from_slice(&[0, 0, 0]);
        let big = bytes.len();
        bytes.extend(
            "Other unsaved application tab"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );
        bytes.extend_from_slice(&[0, 0]);
        let end = bytes.len();
        bytes.extend_from_slice(b"prefix gap");
        let split = bytes.len();
        bytes.extend_from_slice(b"suffix gap");
        let ranges = [
            Region {
                file: 0,
                virtual_start: 0x10000,
                length: end as u64,
            },
            Region {
                file: end as u64,
                virtual_start: 0x200000,
                length: (split - end) as u64,
            },
            Region {
                file: split as u64,
                virtual_start: 0x300000,
                length: (bytes.len() - split) as u64,
            },
        ];
        let mut hits = Vec::new();
        assert!(
            !scan(
                &mut Cursor::new(&bytes),
                &ranges,
                &AtomicBool::new(false),
                |hit| {
                    hits.push(hit);
                    true
                }
            )
            .unwrap()
        );
        for (offset, encoding, expected) in [
            (utf8, "UTF-8", "Customer café has unsaved changes"),
            (wide, "UTF-16LE", "Customer list: Łukasz 😀\rOther customer"),
            (big, "UTF-16BE", "Other unsaved application tab"),
        ] {
            assert!(
                hits.iter().any(|hit| hit.offset == offset as u64
                    && hit.encoding == encoding
                    && hit.text == expected
                    && hit.address == 0x10000 + offset as u64),
                "missing {encoding}"
            );
        }
        assert!(!hits.iter().any(|hit| hit.text.contains("gap")
            && hit.text.contains("prefix")
            && hit.text.contains("suffix")));
        assert!(
            scan(
                &mut Cursor::new(&bytes),
                &ranges,
                &AtomicBool::new(true),
                |_| true
            )
            .is_err()
        );
        assert!(
            scan(
                &mut Cursor::new(&bytes),
                &ranges,
                &AtomicBool::new(false),
                |_| false
            )
            .unwrap()
        );
    }

    #[test]
    fn private_ranges_exclude_images_other_pids_and_unreadable_pages() {
        let table = Table::parse(&json!([
            {"PID":42,"PrivateMemory":true,"Protection":"PAGE_READWRITE","Start VPN":4096,"End VPN":8191},
            {"PID":42,"PrivateMemory":0,"Protection":"PAGE_READWRITE","Start VPN":8192,"End VPN":12287},
            {"PID":42,"PrivateMemory":1,"Protection":"PAGE_READONLY","Start VPN":12288,"End VPN":16383},
            {"PID":43,"PrivateMemory":1,"Protection":"PAGE_READWRITE","Start VPN":16384,"End VPN":20479}
        ]).to_string()).unwrap();
        let ranges = private_ranges(
            table,
            42,
            vec![Region {
                file: 0,
                virtual_start: 0x1000,
                length: 0x5000,
            }],
        )
        .unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            (ranges[0].file, ranges[0].virtual_start, ranges[0].length),
            (0, 4096, 4096)
        );
    }

    #[test]
    fn long_fragments_are_split_with_explicit_boundaries() {
        let bytes = b"customer ".repeat(MAX_TEXT / 4);
        let ranges = [Region {
            file: 0,
            virtual_start: 4096,
            length: bytes.len() as u64,
        }];
        let mut hits = Vec::new();
        scan(
            &mut Cursor::new(&bytes),
            &ranges,
            &AtomicBool::new(false),
            |hit| {
                if hit.encoding == "UTF-8" {
                    hits.push(hit);
                }
                true
            },
        )
        .unwrap();
        assert_eq!(
            hits.iter().map(|hit| hit.text.as_str()).collect::<String>(),
            String::from_utf8(bytes).unwrap()
        );
        assert!(hits[0].boundary.contains("Length limit"));
        assert!(hits[1].boundary.contains("Continuation"));
    }

    #[test]
    fn damaged_encodings_do_not_discard_adjacent_text() {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(b"UTF8 customer before damage");
        bytes.extend_from_slice(&[0xe2, b' ', 0xff]);
        let valid = bytes.len();
        bytes.extend_from_slice("UTF8 customer café after damage".as_bytes());
        bytes.extend([0, 0, 0]);
        let wide = bytes.len();
        bytes.extend(
            "Wide customer before damage"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend(0xd800u16.to_le_bytes());
        bytes.extend(
            "Wide customer after damage"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend([0, 0]);
        let ranges = [Region {
            file: 0,
            virtual_start: 0x10000,
            length: bytes.len() as u64,
        }];
        let mut hits = Vec::new();
        scan(
            &mut Cursor::new(bytes),
            &ranges,
            &AtomicBool::new(false),
            |hit| {
                hits.push(hit);
                true
            },
        )
        .unwrap();
        assert!(hits.iter().any(|h| h.encoding == "UTF-8"
            && h.offset == 1
            && h.text == "UTF8 customer before damage"));
        assert!(hits.iter().any(|h| h.encoding == "UTF-8"
            && h.offset == valid as u64
            && h.text == "UTF8 customer café after damage"));
        assert!(hits.iter().any(|h| h.encoding == "UTF-16LE"
            && h.offset == wide as u64
            && h.text == "Wide customer before damage"));
        assert!(
            hits.iter()
                .any(|h| h.encoding == "UTF-16LE" && h.text == "Wide customer after damage")
        );
    }
}
