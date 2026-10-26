//! Capture quarantine evidence and local blocked outputs, with separate provenance.
mod defender;

use super::{record, table};
use crate::{
    case::{CaseSnapshot, Evidence, Run, RunStatus},
    extracted_files::{self, DUMP_FILES, FileDumpTarget},
    results::{Query, ResultStore, StoredRecord},
    volatility::{Installation, Record, Table},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub const PENDING: &str = "Waiting to recover quarantine metadata after inventories";
pub const HELP: &str = "Collect available FileScan, Handles, PsList, PsScan, CmdLine and NTFS alternate streams. Recover cached Microsoft Defender Quarantine Entries metadata to identify original paths, threat names and quarantine times. Known folders for other antivirus products are labelled path candidates. Correlate process inventory candidates and download origins from alternate streams or existing browser/download reports. Also list locally blocked or unavailable recovered outputs, with antivirus cause unconfirmed. Missing cached bytes do not establish antivirus detection or non-execution. No quarantined payloads are restored. No custom arguments.";
pub const SOURCES: &[&str] = &[
    "windows.filescan.FileScan",
    "windows.handles.Handles",
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.cmdline.CmdLine",
    "windows.mftscan.ADS",
];
const MAX_ROWS: usize = 10_000;

/// Internal snapshots use saved case records only, never the acquisition or engine.
pub fn passive_arguments(arguments: &[String]) -> bool {
    matches!(arguments, [flag, fingerprint] if flag == "--passive"
        && fingerprint.len() == 64 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn is_passive(run: &Run) -> bool {
    run.plugin == super::QUARANTINE && passive_arguments(&run.arguments)
}

fn antivirus_error(message: &str) -> bool {
    let message = message.to_lowercase();
    [
        "os error 225",
        "os error 226",
        "contains a virus",
        "potentially unwanted software",
        "windows defender",
        "antivirus",
        "anti-virus",
        "quarantin",
    ]
    .iter()
    .any(|phrase| message.contains(phrase))
}

/// Plan an automatic refresh only when recorded isolation evidence has changed.
/// Called on a worker; unchanged, active and failed snapshots are not requeued.
pub fn passive_runs(directory: &Path, document: &CaseSnapshot) -> Result<Vec<Run>, String> {
    let mut runs = Vec::new();
    for evidence in &document.evidence {
        if document.runs.iter().any(|r| {
            r.evidence_id == evidence.id
                && r.plugin == super::QUARANTINE
                && matches!(r.status, RunStatus::Queued | RunStatus::Running)
        }) {
            continue;
        }
        let rows = local_rows(
            directory,
            document,
            &evidence.id,
            &[],
            &AtomicBool::new(false),
        )?;
        if rows.is_empty() {
            continue;
        }
        let mut digest = Sha256::new();
        for row in rows {
            digest.update(serde_json::to_vec(&row.fields).map_err(|e| e.to_string())?);
        }
        let mut seen = BTreeSet::new();
        for run in document.runs.iter().rev().filter(|r| {
            r.evidence_id == evidence.id
                && r.status == RunStatus::Completed
                && r.arguments.is_empty()
                && (SOURCES.contains(&r.plugin.as_str())
                    || matches!(r.plugin.as_str(), super::BROWSER | super::DOWNLOADS))
                && seen.insert(r.plugin.clone())
        }) {
            digest.update(run.id.as_bytes());
        }
        let arguments = vec!["--passive".into(), format!("{:x}", digest.finalize())];
        if document.runs.iter().any(|r| {
            r.evidence_id == evidence.id
                && r.plugin == super::QUARANTINE
                && r.arguments == arguments
        }) {
            continue;
        }
        runs.push(super::prepare(evidence, super::QUARANTINE, arguments)?);
    }
    Ok(runs)
}

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Quarantine investigation cancelled".into())
    } else {
        Ok(())
    }
}
fn normal(path: &str) -> String {
    path.trim_matches('"')
        .replace('/', "\\")
        .trim_start_matches(r"\??\")
        .trim_start_matches(r"\\?\")
        .to_lowercase()
}
fn filename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or("")
}

/// A folder identifies a lead, never a confirmed detection.
fn vendor(path: &str) -> Option<(&'static str, bool)> {
    let path = normal(path);
    if path.contains(r"\microsoft\windows defender\quarantine\")
        || path.contains(r"\microsoft\microsoft antimalware\quarantine\")
    {
        return Some(("Microsoft Defender", path.contains(r"\quarantine\entries\")));
    }
    [
        (
            r"\symantec\symantec endpoint protection\",
            "Symantec",
            "quarantine",
        ),
        (r"\mcafee\", "McAfee", "quarantine"),
        (r"\malwarebytes\", "Malwarebytes", "quarantine"),
        (r"\avast software\", "Avast", "chest"),
        (r"\avg\", "AVG", "chest"),
        (r"\eset\", "ESET", "quarantine"),
        (r"\kaspersky lab\", "Kaspersky", "qb"),
        (r"\sophos\", "Sophos", "safestore"),
    ]
    .into_iter()
    .find_map(|(root, product, folder)| {
        (path.contains(root) && path.split('\\').any(|p| p == folder)).then_some((product, false))
    })
}

fn source(row: &StoredRecord, role: &str) -> Value {
    json!({"Role":role,"Run":row.run_id,"Row":row.row,"Record":row.id})
}
fn inputs(document: &CaseSnapshot, run: &Run) -> CaseSnapshot {
    let mut document = document.clone();
    if let Some(index) = document.runs.iter().position(|r| r.id == run.id) {
        document.runs.truncate(index);
    }
    document
}
fn inventory(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &str,
    cancel: &AtomicBool,
) -> Result<Vec<(String, StoredRecord)>, String> {
    let mut seen = BTreeSet::new();
    let store = ResultStore::at(directory);
    let mut records = Vec::new();
    for run in document.runs.iter().rev().filter(|r| {
        r.evidence_id == evidence
            && r.status == RunStatus::Completed
            && r.arguments.is_empty()
            && (SOURCES.contains(&r.plugin.as_str())
                || matches!(r.plugin.as_str(), super::BROWSER | super::DOWNLOADS))
            && seen.insert(r.plugin.clone())
    }) {
        cancelled(cancel)?;
        let ids = store
            .query(&Query {
                runs: vec![run.id.clone()],
                ..Default::default()
            })?
            .ids;
        for chunk in ids.chunks(256) {
            cancelled(cancel)?;
            records.extend(
                store
                    .fetch(chunk)?
                    .into_iter()
                    .map(|row| (run.plugin.clone(), row)),
            );
        }
    }
    Ok(records)
}
fn file_candidate(plugin: &str, row: &Record) -> bool {
    (plugin == SOURCES[0] || plugin == SOURCES[1] && row.text("Type").eq_ignore_ascii_case("File"))
        && vendor(&super::files::file_path(row)).is_some()
        && !super::files::pseudo_file(&super::files::file_path(row))
}

pub fn recovery_runs(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &Evidence,
    engine: &Installation,
) -> Result<Vec<Run>, String> {
    let mut runs = Vec::new();
    let mut existing: BTreeSet<_> = document
        .runs
        .iter()
        .filter(|r| {
            r.evidence_id == evidence.id
                && r.plugin == DUMP_FILES
                && matches!(
                    r.status,
                    RunStatus::Completed | RunStatus::Queued | RunStatus::Running
                )
        })
        .map(|r| r.arguments.clone())
        .collect();
    if engine.plugins.iter().any(|p| p.id == DUMP_FILES) {
        for (plugin, row) in inventory(directory, document, &evidence.id, &AtomicBool::new(false))?
        {
            if !file_candidate(&plugin, &row.record)
                || !vendor(&super::files::file_path(&row.record))
                    .is_some_and(|(_, metadata)| metadata)
            {
                continue;
            }
            let Some(target) = FileDumpTarget::from_record(&plugin, &row.record) else {
                continue;
            };
            let arguments = target.arguments(false);
            if !existing.insert(arguments.clone()) {
                continue;
            }
            if runs.len() >= 512 {
                return Err("More than 512 quarantine metadata objects found. Recover selected Entries files in Files before retrying.".into());
            }
            runs.push(engine.prepare(
                evidence,
                DUMP_FILES,
                arguments,
                &directory.join("analyses"),
            )?);
        }
    }
    runs.push(super::prepare(evidence, super::QUARANTINE, vec![])?);
    Ok(runs)
}

fn empty_row(scope: &str, product: &str, status: &str) -> Record {
    record(
        json!({"Scope":scope,"Antivirus":product,"Evidence status":status,
        "Threat":"Unknown","Filename":"Unknown","Original path":"",
        "Execution evidence":"Unknown; no matching process evidence recovered",
        "Origin evidence":"Unknown; no matching download origin recovered"}),
    )
}

fn capture_rows(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &str,
    records: &[(String, StoredRecord)],
    cancel: &AtomicBool,
) -> Result<Vec<Record>, String> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let dumps: HashMap<_, _> = document
        .runs
        .iter()
        .filter(|r| {
            r.evidence_id == evidence && r.plugin == DUMP_FILES && r.status == RunStatus::Completed
        })
        .map(|r| (r.arguments.clone(), r))
        .collect();
    for (plugin, observation) in records {
        cancelled(cancel)?;
        if !file_candidate(plugin, &observation.record) {
            continue;
        }
        let path = super::files::file_path(&observation.record);
        let Some((product, metadata)) = vendor(&path) else {
            continue;
        };
        let arguments =
            FileDumpTarget::from_record(plugin, &observation.record).map(|t| t.arguments(false));
        if !seen.insert((normal(&path), arguments.clone())) {
            continue;
        }
        let mut base = empty_row("Memory capture", product, "Quarantine folder candidate");
        base.fields
            .insert("Quarantine path".into(), path.clone().into());
        base.fields
            .insert("Filename".into(), filename(&path).into());
        base.fields.insert("Interpretation".into(), "A file object references a known antivirus quarantine folder. This alone does not identify a threat, its original filename, or current quarantine status.".into());
        base.fields.insert(
            "Sources".into(),
            json!([source(observation, "Quarantine file")]),
        );
        let mut parsed = Vec::new();
        let mut diagnostics = Vec::new();
        if metadata {
            if let Some(dump) = arguments.as_ref().and_then(|args| dumps.get(args)) {
                match extracted_files::listing(&directory.join("analyses").join(&dump.id)) {
                    Ok(files) => {
                        if files.is_empty() {
                            diagnostics.push("No cached metadata contents recovered".into());
                        }
                        let mut variants = BTreeSet::new();
                        for file in files {
                            cancelled(cancel)?;
                            let result = (|| {
                                let mut bytes = Vec::new();
                                extracted_files::open_artifact(&file.path)?
                                    .take(defender::MAX_BYTES as u64 + 1)
                                    .read_to_end(&mut bytes)
                                    .map_err(|e| e.to_string())?;
                                defender::parse(&bytes)
                            })();
                            match result {
                                Ok(findings) => {
                                    for finding in findings {
                                        if !variants.insert(
                                            serde_json::to_string(&finding.fields)
                                                .map_err(|e| e.to_string())?,
                                        ) {
                                            continue;
                                        }
                                        let mut row = base.clone();
                                        row.fields.extend(finding.fields);
                                        row.fields.insert(
                                            "Evidence status".into(),
                                            "Confirmed Defender quarantine metadata".into(),
                                        );
                                        row.fields.insert(
                                            "Filename".into(),
                                            filename(&row.text("Original path")).into(),
                                        );
                                        row.fields.insert("Interpretation".into(), "A checksum-validated Defender quarantine entry records this file. The entry does not prove the file was executed or remains quarantined at capture time. Process and origin links are separately labelled candidates.".into());
                                        row.fields.insert("Sources".into(), json!([source(observation, "Quarantine file"),
                                        {"Role":"Defender metadata","Run":dump.id,"File":file.path.file_name().map(|n| n.to_string_lossy())}]));
                                        parsed.push(row);
                                    }
                                }
                                Err(error) => diagnostics.push(format!(
                                    "{}: {error}",
                                    file.path.file_name().unwrap_or_default().to_string_lossy()
                                )),
                            }
                        }
                    }
                    Err(error) => diagnostics.push(error),
                }
            } else {
                diagnostics.push("No completed cached metadata recovery available".into());
            }
        }
        if parsed.is_empty() {
            if metadata && diagnostics.is_empty() {
                diagnostics.push("No file resources found in metadata".into());
            }
            base.fields
                .insert("Recovery details".into(), diagnostics.join("; ").into());
            rows.push(base);
        } else {
            for row in &mut parsed {
                row.fields
                    .insert("Recovery details".into(), diagnostics.join("; ").into());
            }
            rows.extend(parsed);
        }
        if rows.len() >= MAX_ROWS {
            break;
        }
    }
    Ok(rows)
}

fn local_rows(
    directory: &Path,
    document: &CaseSnapshot,
    evidence: &str,
    records: &[(String, StoredRecord)],
    cancel: &AtomicBool,
) -> Result<Vec<Record>, String> {
    let mut original = HashMap::new();
    for (plugin, row) in records {
        if let Some(target) = FileDumpTarget::from_record(plugin, &row.record) {
            original.insert(target.arguments(false), row);
        }
    }
    let runs: HashMap<_, _> = document
        .runs
        .iter()
        .filter(|r| r.evidence_id == evidence && !super::is_native(&r.plugin))
        .map(|r| (r.id.as_str(), r))
        .collect();
    let db = crate::database::connect(directory)?;
    let mut statement = db.prepare("SELECT run_id,name,sha256,blocked_reason FROM analysis_outputs WHERE blocked_reason IS NOT NULL AND name NOT IN ('stdout.json','stderr.log') ORDER BY run_id,name").map_err(|e| e.to_string())?;
    let outputs = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    let mut output_runs = BTreeSet::new();
    for output in outputs {
        cancelled(cancel)?;
        let (id, name, sha256, reason) = output.map_err(|e| e.to_string())?;
        let Some(run) = runs.get(id.as_str()) else {
            continue;
        };
        output_runs.insert(id);
        let path = directory.join("analyses").join(&run.id).join(name);
        let mut row = empty_row(
            "Local computer",
            "Unconfirmed",
            "Recovered output blocked or unavailable",
        );
        row.fields.insert(
            "Local output".into(),
            path.to_string_lossy().to_string().into(),
        );
        row.fields.insert(
            "Filename".into(),
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
                .into(),
        );
        row.fields.insert("Blocked reason".into(), reason.into());
        row.fields
            .insert("Source analysis".into(), run.plugin.clone().into());
        row.fields
            .insert("Source status".into(), run.status.label().into());
        row.fields
            .insert("Analysis diagnostics".into(), run.message.clone().into());
        row.fields.insert("SHA-256".into(), sha256.into());
        let mut sources = vec![json!({"Role":"Local recovery","Run":run.id})];
        if run.plugin == DUMP_FILES
            && let Some(observation) = original.get(&run.arguments)
        {
            let path = super::files::file_path(&observation.record);
            row.fields.insert("Filename".into(), filename(&path).into());
            row.fields.insert("Original path".into(), path.into());
            sources.push(source(observation, "Original file"));
        }
        row.fields.insert("Sources".into(), json!(sources));
        row.fields.insert("Interpretation".into(), "VolGUI recorded a blocked or unavailable recovered output on this computer. Antivirus involvement is unconfirmed. This is separate from quarantine inside the capture; an empty cache extraction is not a detection.".into());
        rows.push(row);
        if rows.len() >= MAX_ROWS {
            return Ok(rows);
        }
    }
    // An engine can fail before it emits a result row or output manifest.
    // Retain that diagnostic as a lead without inventing a file or threat name.
    for run in document.runs.iter().filter(|r| {
        r.evidence_id == evidence
            && !super::is_native(&r.plugin)
            && !matches!(r.status, RunStatus::Queued | RunStatus::Running)
            && !output_runs.contains(&r.id)
            && antivirus_error(&r.message)
    }) {
        cancelled(cancel)?;
        let mut row = empty_row(
            "Local computer",
            if run.message.to_lowercase().contains("defender") {
                "Microsoft Defender"
            } else {
                "Unconfirmed"
            },
            "Antivirus interruption reported",
        );
        row.fields
            .insert("Filename".into(), "Target not recorded".into());
        row.fields
            .insert("Source analysis".into(), run.plugin.clone().into());
        row.fields
            .insert("Source status".into(), run.status.label().into());
        row.fields
            .insert("Blocked reason".into(), run.message.clone().into());
        row.fields
            .insert("Analysis diagnostics".into(), run.message.clone().into());
        row.fields.insert(
            "Sources".into(),
            json!([{"Role":"Interrupted analysis", "Run":run.id}]),
        );
        row.fields.insert("Interpretation".into(), "The analysis diagnostics report antivirus interference on this computer. No isolated filename or threat identity was recorded. Open the interrupted analysis for its command and diagnostics.".into());
        rows.push(row);
        if rows.len() >= MAX_ROWS {
            break;
        }
    }
    Ok(rows)
}

fn executable(command: &str) -> String {
    let command = command.trim();
    command
        .strip_prefix('"')
        .map(|v| v.split('"').next().unwrap_or(""))
        .unwrap_or_else(|| command.split_whitespace().next().unwrap_or(""))
        .to_string()
}
fn comparable_paths(a: &str, b: &str) -> bool {
    (a.as_bytes().get(1) == Some(&b':') && b.as_bytes().get(1) == Some(&b':'))
        || (a.starts_with(r"\device\") && b.starts_with(r"\device\"))
        || (a.starts_with(r"\\") && b.starts_with(r"\\"))
}
fn match_path(original: &str, candidate: &str) -> Option<&'static str> {
    let a = normal(original);
    let b = normal(candidate);
    if a.is_empty() || b.is_empty() {
        return None;
    }
    if a == b {
        return Some("Full path match; file identity unconfirmed");
    }
    if comparable_paths(&a, &b) {
        return None;
    }
    filename(&a)
        .eq_ignore_ascii_case(filename(&b))
        .then_some("Filename only; file identity unconfirmed")
}

fn correlate(
    findings: Vec<Record>,
    records: &[(String, StoredRecord)],
    cancel: &AtomicBool,
) -> Result<Vec<Record>, String> {
    let mut commands: HashMap<String, Vec<(String, &StoredRecord)>> = HashMap::new();
    let mut processes: HashMap<String, Vec<(&str, &StoredRecord)>> = HashMap::new();
    let mut origins: HashMap<String, Vec<(Record, Value)>> = HashMap::new();
    for (plugin, source_row) in records {
        cancelled(cancel)?;
        let row = &source_row.record;
        match plugin.as_str() {
            "windows.cmdline.CmdLine" => {
                commands
                    .entry(row.text("PID"))
                    .or_default()
                    .push((executable(&row.text("Args")), source_row));
            }
            "windows.pslist.PsList" | "windows.psscan.PsScan" => {
                let name = [row.text("ImageFileName"), row.text("Name")]
                    .into_iter()
                    .find(|s| !s.is_empty())
                    .unwrap_or_default();
                processes
                    .entry(filename(&normal(&name)).to_string())
                    .or_default()
                    .push((plugin, source_row));
            }
            "windows.mftscan.ADS" => {
                if let Some(origin) = super::downloads::zone_origin(row) {
                    origins
                        .entry(normal(&origin.text("Filename")))
                        .or_default()
                        .push((origin, source(source_row, "Download origin")));
                }
            }
            super::BROWSER | super::DOWNLOADS
                if !row.text("URL").is_empty()
                    && !row.text("Filename").is_empty()
                    && (row.text("Kind") == "Download"
                        || row.text("Kind") == "Download origin") =>
            {
                origins
                    .entry(normal(&row.text("Filename")))
                    .or_default()
                    .push((row.clone(), source(source_row, "Download origin")));
            }
            _ => {}
        }
    }
    let mut rows = Vec::new();
    for finding in findings {
        cancelled(cancel)?;
        let original = finding.text("Original path");
        // A quarantine container's opaque name is never treated as the original malware filename.
        let key = filename(&normal(&original)).to_string();
        let mut variants = Vec::new();
        for (plugin, process) in processes.get(&key).into_iter().flatten() {
            let pid = process.record.text("PID");
            let Some(pid_number) = super::process_memory::number(&process.record, "PID") else {
                continue;
            };
            let candidates = commands.get(&pid);
            // CmdLine describes the active process. A scanned object may be an
            // earlier lifetime of the same PID, so it cannot inherit that path.
            let command = candidates
                .filter(|v| *plugin == "windows.pslist.PsList" && v.len() == 1)
                .and_then(|v| v.first());
            let candidate = command.map(|(path, _)| path.clone()).unwrap_or_else(|| {
                let image = process.record.text("ImageFileName");
                if image.is_empty() {
                    process.record.text("Name")
                } else {
                    image
                }
            });
            let Some(basis) = match_path(&original, &candidate) else {
                continue;
            };
            let mut row = finding.clone();
            row.fields.insert("PID".into(), pid_number.into());
            row.fields.insert("Match basis".into(), basis.into());
            let exit = process.record.text("ExitTime");
            let exited = !matches!(exit.as_str(), "" | "N/A" | "-" | "null");
            row.fields.insert(
                "Execution evidence".into(),
                if exited {
                    "Exited process candidate"
                } else if *plugin == "windows.pslist.PsList" {
                    "Active process candidate at capture (PsList)"
                } else {
                    "Scanned process candidate; running state unknown"
                }
                .into(),
            );
            for field in ["CreateTime", "ExitTime"] {
                if let Some(value) = process.record.fields.get(field) {
                    row.fields.insert(field.into(), value.clone());
                }
            }
            if let Some(Value::Array(sources)) = row.fields.get_mut("Sources") {
                sources.push(source(process, "Process"));
                if let Some((_, command)) = command {
                    sources.push(source(command, "Command executable"));
                }
            }
            variants.push(row);
            if variants.len() >= MAX_ROWS {
                break;
            }
        }
        if variants.is_empty() {
            variants.push(finding);
        }
        for variant in variants {
            let mut matched = false;
            for (origin, proof) in origins.get(&key).into_iter().flatten() {
                let candidate = if origin.text("Path").is_empty() {
                    origin.text("Filename")
                } else {
                    origin.text("Path")
                };
                let Some(basis) = match_path(&original, &candidate) else {
                    continue;
                };
                let mut row = variant.clone();
                row.fields.insert(
                    "Origin evidence".into(),
                    format!("{}; {basis}", origin.text("Download evidence")).into(),
                );
                for field in ["URL", "Website URL"] {
                    if let Some(value) = origin.fields.get(field) {
                        row.fields.insert(field.into(), value.clone());
                    }
                }
                if let Some(Value::Array(sources)) = row.fields.get_mut("Sources") {
                    sources.push(proof.clone());
                }
                rows.push(row);
                matched = true;
                if rows.len() >= MAX_ROWS {
                    return Ok(rows);
                }
            }
            if !matched {
                rows.push(variant);
            }
            if rows.len() >= MAX_ROWS {
                return Ok(rows);
            }
        }
    }
    Ok(rows)
}

pub fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    cancelled(cancel)?;
    let document = inputs(document, run);
    progress("Reading quarantine file objects and local blocked output records".into());
    let records = inventory(directory, &document, &run.evidence_id, cancel)?;
    let mut findings = capture_rows(directory, &document, &run.evidence_id, &records, cancel)?;
    findings.extend(local_rows(
        directory,
        &document,
        &run.evidence_id,
        &records,
        cancel,
    )?);
    progress("Matching original paths to process and download evidence".into());
    let rows = correlate(findings, &records, cancel)?;
    let missing = SOURCES
        .iter()
        .filter(|plugin| {
            !document.runs.iter().any(|r| {
                r.plugin == **plugin
                    && r.evidence_id == run.evidence_id
                    && r.arguments.is_empty()
                    && r.status == RunStatus::Completed
            })
        })
        .copied()
        .collect::<Vec<_>>();
    let mut message = format!(
        "{} quarantine and local availability findings. Memory capture and Local computer scopes are separate. Unknown execution or origin means evidence was not recovered. Folder matches and local blocking do not confirm antivirus detection. Defender payloads remain isolated.",
        rows.len()
    );
    if !missing.is_empty() {
        message.push_str(&format!(
            " Missing source inventories: {}.",
            missing.join(", ")
        ));
    }
    if rows.len() >= MAX_ROWS {
        message.push_str(" Result limit reached: 10,000 findings. Narrow the source inventories for further review.");
    }
    Ok((table(rows), message))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_rules_do_not_treat_arbitrary_quarantine_folders_as_antivirus() {
        assert!(vendor(r"C:\Users\Alice\quarantine\bad.exe").is_none());
        assert_eq!(
            vendor(
                r"\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Quarantine\Entries\{id}"
            ),
            Some(("Microsoft Defender", true))
        );
        assert_eq!(
            vendor(r"C:\ProgramData\Malwarebytes\MBAMService\Quarantine\entry"),
            Some(("Malwarebytes", false))
        );
        assert!(match_path(r"C:\Downloads\bad.exe", r"D:\Other\bad.exe").is_none());
        assert!(
            match_path(r"C:\Downloads\bad.exe", "bad.exe")
                .unwrap()
                .starts_with("Filename only")
        );
    }
}
