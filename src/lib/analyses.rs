// Builds analysis drafts and retry queues.
//! Analysis chooser policy and per-evidence selections.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use crate::{
    artifacts::OperatingSystem,
    case::{Case, Evidence, Result, Run, RunStatus},
    volatility::{Installation, Plugin, parse_arguments},
};

/// Select the next job in queue order without exceeding the global limit.
/// Recovery parsers wait for preceding dumps and block later jobs until complete.
pub fn next_queued_run(runs: &[Run], limit: std::num::NonZeroUsize) -> Option<usize> {
    let running = runs.iter().filter(|run| run.status == RunStatus::Running);
    if running.clone().count() >= limit.get() || running.clone().any(is_recovery_run) {
        return None;
    }
    let index = runs
        .iter()
        .position(|run| {
            run.status == RunStatus::Queued && crate::analysis::quarantine::is_passive(run)
        })
        .or_else(|| runs.iter().position(|run| run.status == RunStatus::Queued))?;
    if is_recovery_run(&runs[index]) && running.count() > 0 {
        return None;
    }
    Some(index)
}

fn is_recovery_run(run: &Run) -> bool {
    !crate::analysis::quarantine::is_passive(run) && is_recovery_analysis(&run.plugin)
}

fn is_recovery_analysis(plugin: &str) -> bool {
    matches!(
        plugin,
        crate::analysis::BROWSER
            | crate::analysis::APPLICATION
            | crate::analysis::NETWORK
            | crate::analysis::FILES
            | crate::analysis::DOWNLOADS
            | crate::analysis::QUARANTINE
    )
}

pub const APPLICATION_RECOVERY_PENDING: &str = "Waiting to prepare process memory recovery";

pub fn prepare_file_recovery(case: &Case, engine: &Installation, run: &Run) -> Result<Vec<Run>> {
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    let mut document = case.document.clone();
    if let Some(index) = document.runs.iter().position(|r| r.id == run.id) {
        document.runs.truncate(index);
    }
    let mut runs = crate::analysis::files::recovery_runs(
        &case.directory,
        &document,
        evidence,
        engine,
        &run.arguments,
    )?;
    let parser = runs.last_mut().ok_or("Missing file recovery report")?;
    parser.id = run.id.clone();
    parser.created_at = run.created_at.clone();
    Ok(runs)
}

/// Replace a deferred application job with its pinned inputs and parser job.
pub fn prepare_application_recovery(
    case: &Case,
    engine: &Installation,
    run: &Run,
) -> Result<Vec<Run>> {
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    // Later jobs must never become inputs to an earlier recovery request.
    let mut document = case.document.clone();
    if let Some(index) = document.runs.iter().position(|r| r.id == run.id) {
        document.runs.truncate(index);
    }
    let mut runs = crate::analysis::application::recovery_runs(
        &case.directory,
        &document,
        evidence,
        engine,
        &run.arguments,
        &std::sync::atomic::AtomicBool::new(false),
    )?;
    let parser = runs.last_mut().ok_or("Missing application parser job")?;
    parser.id = run.id.clone();
    parser.created_at = run.created_at.clone();
    Ok(runs)
}

pub const BROWSER_RECOVERY_PENDING: &str =
    "Waiting to prepare browser recovery after prerequisites";

pub fn prepare_quarantine_recovery(
    case: &Case,
    engine: &Installation,
    run: &Run,
) -> Result<Vec<Run>> {
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    let mut document = case.document.clone();
    if let Some(index) = document.runs.iter().position(|r| r.id == run.id) {
        document.runs.truncate(index);
    }
    let mut runs =
        crate::analysis::quarantine::recovery_runs(&case.directory, &document, evidence, engine)?;
    let report = runs.last_mut().ok_or("Missing quarantine report")?;
    report.id = run.id.clone();
    report.created_at = run.created_at.clone();
    Ok(runs)
}

pub fn prepare_download_recovery(
    case: &Case,
    engine: &Installation,
    run: &Run,
) -> Result<Vec<Run>> {
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    let mut document = case.document.clone();
    if let Some(index) = document.runs.iter().position(|r| r.id == run.id) {
        document.runs.truncate(index);
    }
    let mut runs = if engine
        .plugins
        .iter()
        .any(|p| p.id == crate::extracted_files::DUMP_FILES)
    {
        crate::analysis::browser_recovery_runs(
            &case.directory,
            &document,
            evidence,
            engine,
            false,
            &std::sync::atomic::AtomicBool::new(false),
        )?
    } else {
        Vec::new()
    };
    runs.retain(|r| r.plugin != crate::analysis::BROWSER);
    let mut report = run.clone();
    report.message.clear();
    runs.push(report);
    Ok(runs)
}

/// Resolve a deferred browser job using results from the jobs ahead of it.
pub fn prepare_browser_recovery(case: &Case, engine: &Installation, run: &Run) -> Result<Vec<Run>> {
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Evidence is no longer available")?;
    let mut draft = AnalysisDraft::new(evidence);
    draft.selected.insert(crate::analysis::BROWSER.into());
    let mut runs = draft.prepare_in_case(engine, evidence, case)?;
    if runs
        .iter()
        .any(|run| run.message == BROWSER_RECOVERY_PENDING)
    {
        return Err("Browser recovery prerequisites did not complete successfully".into());
    }
    runs.retain(|run| run.plugin != crate::analysis::BROWSER);
    Ok(runs)
}

/// Inputs consumed by investigation views or their recovery pipelines.
/// System information is also basic as a useful preprocessing overview.
/// Bulk file recovery and other generic artifact shortcuts remain extended.
pub fn basic_label(id: &str) -> Option<&'static str> {
    Some(match id {
        crate::analysis::NETWORK => "Network investigation and correlation",
        crate::analysis::DOWNLOADS => "Download and execution investigation",
        crate::analysis::QUARANTINE => "Quarantined threats and execution investigation",
        crate::analysis::BROWSER => "Browser recovery and analysis",
        "windows.info.Info" => "System information",
        REGISTRY_ALL => "All registry subkeys",
        "windows.pslist.PsList" | "linux.pslist.PsList" | "mac.pslist.PsList" => "Processes",
        "windows.pstree.PsTree" | "linux.pstree.PsTree" | "mac.pstree.PsTree" => "Process tree",
        "windows.psscan.PsScan" => "Process scan",
        "windows.cmdline.CmdLine" => "Command lines",
        "windows.mftscan.ADS" => "Download origins and alternate data streams",
        "windows.malware.psxview.PsXView" => "Cross-check hidden processes",
        "windows.netscan.NetScan"
        | "windows.netstat.NetStat"
        | "linux.sockstat.Sockstat"
        | "mac.netstat.Netstat" => "Network connections",
        "windows.dlllist.DllList" => "Loaded DLLs",
        "windows.filescan.FileScan" | "linux.lsof.Lsof" | "mac.lsof.Lsof" => "File scan",
        "windows.dumpfiles.DumpFiles" => "Dump files",
        "windows.handles.Handles" => "Process handles",
        "windows.registry.printkey.PrintKey" => "Registry key contents",
        "windows.vadinfo.VadInfo" => "Process memory regions and dumps",
        "windows.memmap.Memmap" => "Process memory map and dump",
        "windows.registry.hivelist.HiveList" | "windows.registry.hivescan.HiveScan" => {
            "Registry hives"
        }
        "windows.consoles.Consoles" => "Console history",
        "windows.cmdscan.CmdScan" => "Scanned command history",
        _ => return None,
    })
}

/// Composite choices expand into ordinary jobs so each recovery has its own history.
pub const REGISTRY_ALL: &str = "windows.registry.AllSubkeys";

pub fn application_plugins(plugins: &[Plugin]) -> Vec<Plugin> {
    let mut catalog = plugins.to_vec();
    catalog.extend([
        Plugin {
            id: crate::analysis::QUARANTINE.into(),
            description: crate::analysis::quarantine::HELP.into(),
        },
        Plugin {
            id: crate::analysis::DOWNLOADS.into(),
            description: crate::analysis::downloads::HELP.into(),
        },
        Plugin {
            id: crate::analysis::FILES.into(),
            description: "File and document recovery. Collect FileScan and file handles, then attempt recovery of each distinct file object. Prepare cached files for hex, text, SQLite inspection and export. Hide confirmed unavailable files with the Files toggle. Large captures can queue many extraction jobs. Optional --physical uses older FileScan physical offsets.".into(),
        },
        Plugin {
            id: crate::analysis::NETWORK.into(),
            description: "Collect available Windows sockets, processes, command lines, console history and handles. Correlate SMB shares and explicit connection commands in collected records. Credentials are read only when present in a network drive command. Also recovers structurally validated Meterpreter TCP configurations from acquisition bytes. Does not search raw memory for credentials or arbitrary connection strings. Findings retain source record provenance or acquisition offsets.".into(),
        },
        Plugin {
            id: crate::analysis::APPLICATION.into(),
            description: "Choose a PID to recover text from that process's memory. Automatically collects processes, command lines, memory regions and dumps. Inspect hex and decoded text together, including old edits and partial buffers.".into(),
        },
        Plugin {
            id: crate::analysis::BROWSER.into(),
            description: "Recover and parse browser memory, history and saved tabs. Requires unfiltered PsList, CmdLine and FileScan jobs, completed or queued before this analysis. Does not collect prerequisites.".into(),
        },
        Plugin {
            id: REGISTRY_ALL.into(),
            description: "Read all registry subkeys and values recursively across all hives using PrintKey --recurse.".into(),
        },
    ]);
    catalog
}

/// Queue fresh attempts and dismiss the originals from the queue, preserving history.
pub fn queue_retries(case: &mut Case, engine: &Installation, ids: &[String]) -> Result<usize> {
    queue_retries_with_engine(case, Some(engine), ids)
}

pub fn queue_retries_with_engine(
    case: &mut Case,
    engine: Option<&Installation>,
    ids: &[String],
) -> Result<usize> {
    let runs = ids
        .iter()
        .map(|id| {
            let previous = case
                .document
                .runs
                .iter()
                .find(|run| run.id == *id)
                .ok_or("Analysis is no longer available")?;
            if !matches!(previous.status, RunStatus::Failed | RunStatus::Interrupted) {
                return Err("Only failed or interrupted analyses can be retried".into());
            }
            let evidence = case
                .document
                .evidence
                .iter()
                .find(|e| e.id == previous.evidence_id)
                .ok_or("Evidence is no longer available")?;
            if crate::analysis::is_native(&previous.plugin) {
                let mut run = crate::analysis::prepare(
                    evidence,
                    &previous.plugin,
                    if previous.plugin == crate::analysis::APPLICATION {
                        crate::analysis::application::user_arguments(&previous.arguments)?
                    } else {
                        previous.arguments.clone()
                    },
                )?;
                if previous.plugin == crate::analysis::BROWSER {
                    run.message = BROWSER_RECOVERY_PENDING.into();
                }
                if previous.plugin == crate::analysis::APPLICATION {
                    run.message = APPLICATION_RECOVERY_PENDING.into();
                }
                if previous.plugin == crate::analysis::FILES {
                    run.message = crate::analysis::files::PENDING.into();
                }
                if previous.plugin == crate::analysis::DOWNLOADS {
                    run.message = crate::analysis::downloads::PENDING.into();
                }
                if previous.plugin == crate::analysis::QUARANTINE
                    && engine.is_some()
                    && !crate::analysis::quarantine::is_passive(previous)
                {
                    run.message = crate::analysis::quarantine::PENDING.into();
                }
                return Ok(run);
            }
            engine.ok_or("Configure Volatility in settings")?.prepare(
                evidence,
                &previous.plugin,
                previous.arguments.clone(),
                &case.directory.join("analyses"),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let count = runs.len();
    let previous_cleared = case.document.cleared_queue_runs.clone();
    case.document.cleared_queue_runs.extend(ids.iter().cloned());
    if let Err(error) = case.queue_batch(runs) {
        case.document.cleared_queue_runs = previous_cleared;
        return Err(error);
    }
    Ok(count)
}

pub fn chooser_plugins(
    plugins: &[Plugin],
    os: OperatingSystem,
    extended: bool,
    query: &str,
) -> Vec<Plugin> {
    let query = query.to_lowercase();
    let mut plugins: Vec<_> = plugins
        .iter()
        .filter(|plugin| {
            !matches!(
                plugin.id.as_str(),
                crate::analysis::APPLICATION | crate::analysis::STRINGS
            ) && (os.accepts(&plugin.id)
                && (!is_recovery_analysis(&plugin.id)
                    || matches!(os, OperatingSystem::Windows | OperatingSystem::Unknown)))
                && (extended || basic_label(&plugin.id).is_some())
                && format!(
                    "{} {} {}",
                    plugin.id,
                    plugin.description,
                    basic_label(&plugin.id).unwrap_or("")
                )
                .to_lowercase()
                .contains(&query)
        })
        .cloned()
        .collect();
    plugins.sort_by(|a, b| {
        (basic_label(&a.id).is_none(), &a.id).cmp(&(basic_label(&b.id).is_none(), &b.id))
    });
    plugins
}

#[derive(Clone, Debug)]
pub struct AnalysisDraft {
    pub evidence_id: String,
    pub os: OperatingSystem,
    pub selected: BTreeSet<String>,
    pub arguments: BTreeMap<String, String>,
    selection_anchor: Option<String>,
}
impl AnalysisDraft {
    pub fn new(evidence: &Evidence) -> Self {
        Self {
            evidence_id: evidence.id.clone(),
            os: if evidence.operating_system == OperatingSystem::Unknown {
                OperatingSystem::Windows
            } else {
                evidence.operating_system
            },
            selected: BTreeSet::new(),
            arguments: BTreeMap::new(),
            selection_anchor: None,
        }
    }
    pub fn set_os(&mut self, os: OperatingSystem) {
        self.os = os;
        self.selected.retain(|id| os.accepts(id));
        self.selection_anchor = None;
    }
    /// Apply a checkbox action in the current displayed order, including filtered ranges.
    pub fn select(&mut self, id: &str, checked: bool, shift: bool, visible: &[String]) {
        let target = visible.iter().position(|item| item == id);
        let anchor = self
            .selection_anchor
            .as_ref()
            .and_then(|anchor| visible.iter().position(|item| item == anchor));
        let range = match (shift, anchor, target) {
            (true, Some(anchor), Some(target)) => anchor.min(target)..=anchor.max(target),
            (_, _, Some(target)) => {
                self.selection_anchor = Some(id.into());
                target..=target
            }
            _ => return,
        };
        for id in &visible[range] {
            if checked {
                self.selected.insert(id.clone());
            } else {
                self.selected.remove(id);
            }
        }
    }
    pub fn prepare_in_case(
        &self,
        engine: &Installation,
        evidence: &Evidence,
        case: &Case,
    ) -> Result<Vec<Run>> {
        let mut ordinary = self.clone();
        let browser = ordinary.selected.remove(crate::analysis::BROWSER);
        let application = ordinary.selected.remove(crate::analysis::APPLICATION);
        let network = ordinary.selected.remove(crate::analysis::NETWORK);
        let files = ordinary.selected.remove(crate::analysis::FILES);
        let downloads = ordinary.selected.remove(crate::analysis::DOWNLOADS);
        let quarantine = ordinary.selected.remove(crate::analysis::QUARANTINE);
        let registry = ordinary.selected.remove(REGISTRY_ALL);
        for id in [
            crate::analysis::BROWSER,
            crate::analysis::NETWORK,
            crate::analysis::DOWNLOADS,
            crate::analysis::QUARANTINE,
            REGISTRY_ALL,
        ] {
            if self.selected.contains(id)
                && self
                    .arguments
                    .get(id)
                    .is_some_and(|args| !args.trim().is_empty())
            {
                return Err(format!("{id} does not accept custom arguments"));
            }
        }
        let mut runs = ordinary.prepare(engine, evidence, &case.directory.join("analyses"))?;
        if files {
            if self.os != OperatingSystem::Windows {
                return Err("File and document recovery requires Windows evidence".into());
            }
            if !engine
                .plugins
                .iter()
                .any(|p| p.id == crate::extracted_files::DUMP_FILES)
            {
                return Err("File recovery requires the windows.dumpfiles.DumpFiles plugin".into());
            }
            let arguments = parse_arguments(
                self.arguments
                    .get(crate::analysis::FILES)
                    .map(String::as_str)
                    .unwrap_or(""),
            )?;
            let mut report = crate::analysis::prepare(evidence, crate::analysis::FILES, arguments)?;
            for plugin in crate::analysis::files::SOURCES {
                if !case.document.runs.iter().chain(runs.iter()).any(|r| {
                    r.evidence_id == evidence.id
                        && r.plugin == plugin
                        && r.arguments.is_empty()
                        && matches!(
                            r.status,
                            RunStatus::Completed | RunStatus::Queued | RunStatus::Running
                        )
                }) {
                    // FileScan is required. Handles add process ownership when supported.
                    if plugin == crate::analysis::files::SOURCES[0]
                        || engine.plugins.iter().any(|p| p.id == plugin)
                    {
                        runs.push(engine.prepare(
                            evidence,
                            plugin,
                            vec![],
                            &case.directory.join("analyses"),
                        )?);
                    }
                }
            }
            report.message = crate::analysis::files::PENDING.into();
            runs.push(report);
        }
        if network {
            if self.os != OperatingSystem::Windows {
                return Err("Network investigation currently requires Windows evidence".into());
            }
            for plugin in crate::analysis::network::SOURCES {
                if engine.plugins.iter().any(|p| p.id == *plugin)
                    && !case.document.runs.iter().chain(runs.iter()).any(|r| {
                        r.evidence_id == evidence.id
                            && r.plugin == *plugin
                            && r.arguments.is_empty()
                            && matches!(
                                r.status,
                                RunStatus::Completed | RunStatus::Queued | RunStatus::Running
                            )
                    })
                {
                    runs.push(engine.prepare(
                        evidence,
                        plugin,
                        vec![],
                        &case.directory.join("analyses"),
                    )?);
                }
            }
            runs.push(crate::analysis::prepare(
                evidence,
                crate::analysis::NETWORK,
                vec![],
            )?);
        }
        if application {
            if self.os != OperatingSystem::Windows {
                return Err("Process Memory recovery requires Windows evidence".into());
            }
            let arguments = parse_arguments(
                self.arguments
                    .get(crate::analysis::APPLICATION)
                    .map(String::as_str)
                    .unwrap_or(""),
            )?;
            let arguments = crate::analysis::application::user_arguments(&arguments)?;
            crate::analysis::application::target_pid(&arguments)?;
            // Validate engine capabilities before saving any part of the batch.
            for plugin in [
                crate::analysis::application::MEMMAP,
                crate::analysis::application::VADINFO,
            ] {
                if !engine.plugins.iter().any(|p| p.id == plugin) {
                    return Err(format!(
                        "Process Memory recovery requires the {plugin} plugin"
                    ));
                }
            }
            for plugin in crate::analysis::application::INVENTORY {
                if !case.document.runs.iter().chain(runs.iter()).any(|r| {
                    r.evidence_id == evidence.id
                        && r.plugin == plugin
                        && r.arguments.is_empty()
                        && matches!(
                            r.status,
                            RunStatus::Completed | RunStatus::Queued | RunStatus::Running
                        )
                }) {
                    runs.push(engine.prepare(
                        evidence,
                        plugin,
                        vec![],
                        &case.directory.join("analyses"),
                    )?);
                }
            }
            let mut run =
                crate::analysis::prepare(evidence, crate::analysis::APPLICATION, arguments)?;
            run.message = APPLICATION_RECOVERY_PENDING.into();
            runs.push(run);
        }
        if registry {
            if self.os != OperatingSystem::Windows {
                return Err("Recursive registry analysis requires Windows evidence".into());
            }
            runs.push(engine.prepare(
                evidence,
                crate::analysis::registry::PRINT_KEY,
                vec!["--recurse".into()],
                &case.directory.join("analyses"),
            )?);
        }
        if downloads {
            if self.os != OperatingSystem::Windows {
                return Err("Download investigation requires Windows evidence".into());
            }
            for plugin in crate::analysis::downloads::SOURCES {
                if engine.plugins.iter().any(|p| p.id == *plugin)
                    && !case.document.runs.iter().chain(runs.iter()).any(|r| {
                        r.evidence_id == evidence.id
                            && r.plugin == *plugin
                            && r.arguments.is_empty()
                            && matches!(
                                r.status,
                                RunStatus::Completed | RunStatus::Queued | RunStatus::Running
                            )
                    })
                {
                    runs.push(engine.prepare(
                        evidence,
                        plugin,
                        vec![],
                        &case.directory.join("analyses"),
                    )?);
                }
            }
            let mut report =
                crate::analysis::prepare(evidence, crate::analysis::DOWNLOADS, vec![])?;
            report.message = crate::analysis::downloads::PENDING.into();
            runs.push(report);
        }
        if quarantine {
            if self.os != OperatingSystem::Windows {
                return Err("Quarantine investigation requires Windows evidence".into());
            }
            for plugin in crate::analysis::quarantine::SOURCES {
                if engine.plugins.iter().any(|p| p.id == *plugin)
                    && !case.document.runs.iter().chain(runs.iter()).any(|r| {
                        r.evidence_id == evidence.id
                            && r.plugin == *plugin
                            && r.arguments.is_empty()
                            && matches!(
                                r.status,
                                RunStatus::Completed | RunStatus::Queued | RunStatus::Running
                            )
                    })
                {
                    runs.push(engine.prepare(
                        evidence,
                        plugin,
                        vec![],
                        &case.directory.join("analyses"),
                    )?);
                }
            }
            let mut report =
                crate::analysis::prepare(evidence, crate::analysis::QUARANTINE, vec![])?;
            report.message = crate::analysis::quarantine::PENDING.into();
            runs.push(report);
        }
        if browser {
            if self.os != OperatingSystem::Windows {
                return Err("Browser recovery requires Windows evidence".into());
            }
            let missing: Vec<_> = [
                "windows.pslist.PsList",
                "windows.cmdline.CmdLine",
                "windows.filescan.FileScan",
            ]
            .into_iter()
            .filter(|plugin| {
                !case.document.runs.iter().any(|run| {
                    run.evidence_id == evidence.id
                        && run.plugin == *plugin
                        && run.arguments.is_empty()
                        && run.status == RunStatus::Completed
                })
            })
            .collect();
            if !missing.is_empty()
                || runs.iter().any(|run| {
                    matches!(
                        run.plugin.as_str(),
                        "windows.pslist.PsList"
                            | "windows.cmdline.CmdLine"
                            | "windows.filescan.FileScan"
                    )
                })
            {
                let unavailable: Vec<_> = missing
                    .iter()
                    .copied()
                    .filter(|plugin| {
                        !case.document.runs.iter().chain(runs.iter()).any(|run| {
                            run.evidence_id == evidence.id
                                && run.plugin == *plugin
                                && run.arguments.is_empty()
                                && matches!(run.status, RunStatus::Queued | RunStatus::Running)
                        })
                    })
                    .collect();
                if !unavailable.is_empty() {
                    return Err(format!(
                        "Browser recovery requires completed or preceding queued prerequisite jobs for this evidence with no filters: {}",
                        unavailable.join(", ")
                    ));
                }
                let mut run = crate::analysis::prepare(evidence, crate::analysis::BROWSER, vec![])?;
                run.message = BROWSER_RECOVERY_PENDING.into();
                runs.push(run);
                return Ok(runs);
            }
            let mut browser_evidence = evidence.clone();
            browser_evidence.operating_system = self.os;
            let evidence = &browser_evidence;
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let mut memory = match crate::analysis::browser_memory_runs(
                &case.directory,
                &case.document,
                evidence,
                engine,
                &cancel,
            ) {
                Ok(runs) => runs,
                Err(error)
                    if error == "Collect browser processes first, then recover browser memory" =>
                {
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            memory.retain(|run| run.plugin != crate::analysis::BROWSER);
            runs.extend(memory);
            runs.extend(crate::analysis::browser_recovery_runs(
                &case.directory,
                &case.document,
                evidence,
                engine,
                false,
                &cancel,
            )?);
        }
        Ok(runs)
    }

    pub fn prepare(
        &self,
        engine: &Installation,
        evidence: &Evidence,
        directory: &Path,
    ) -> Result<Vec<Run>> {
        if self.evidence_id != evidence.id {
            return Err("The analysis selection refers to different evidence".into());
        }
        // Validate the complete selection before any run is saved or started.
        let mut selected: Vec<_> = self.selected.iter().collect();
        selected.sort_by_key(|id| (basic_label(id).is_none(), *id));
        selected
            .into_iter()
            .map(|id| {
                if !self.os.accepts(id) {
                    return Err(format!("{id} does not match the evidence OS"));
                }
                let arguments =
                    parse_arguments(self.arguments.get(id).map(String::as_str).unwrap_or(""))
                        .map_err(|error| format!("{id}: {error}"))?;
                engine.prepare(evidence, id, arguments, directory)
            })
            .collect()
    }
}
