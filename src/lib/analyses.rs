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
/// Browser parsing waits for preceding dumps and blocks later jobs until complete.
pub fn next_queued_run(runs: &[Run], limit: std::num::NonZeroUsize) -> Option<usize> {
    let running = runs.iter().filter(|run| run.status == RunStatus::Running);
    if running.clone().count() >= limit.get()
        || running
            .clone()
            .any(|run| run.plugin == crate::analysis::BROWSER)
    {
        return None;
    }
    let index = runs
        .iter()
        .position(|run| run.status == RunStatus::Queued)?;
    if runs[index].plugin == crate::analysis::BROWSER && running.count() > 0 {
        return None;
    }
    Some(index)
}

pub const BROWSER_RECOVERY_PENDING: &str =
    "Waiting to prepare browser recovery after prerequisites";

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

/// The common investigation tasks shown before the full plugin catalog.
pub fn basic_label(id: &str) -> Option<&'static str> {
    Some(match id {
        crate::analysis::BROWSER => "Browser recovery and analysis",
        REGISTRY_ALL => "All registry subkeys",
        "windows.info.Info" => "System information",
        "windows.pslist.PsList" | "linux.pslist.PsList" | "mac.pslist.PsList" => "Processes",
        "windows.pstree.PsTree" | "linux.pstree.PsTree" | "mac.pstree.PsTree" => "Process tree",
        "windows.psscan.PsScan" => "Process scan",
        "windows.cmdline.CmdLine" => "Command lines",
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
        "linux.bash.Bash" | "mac.bash.Bash" => "Shell history",
        "windows.malware.malfind.Malfind" => "Suspicious memory",
        "windows.modules.Modules" | "linux.lsmod.Lsmod" | "mac.lsmod.Lsmod" => "Loaded modules",
        "windows.consoles.Consoles" => "Console history",
        "windows.sessions.Sessions" => "User sessions",
        _ => return None,
    })
}

/// Composite choices expand into ordinary jobs so each recovery has its own history.
pub const REGISTRY_ALL: &str = "windows.registry.AllSubkeys";

pub fn application_plugins(plugins: &[Plugin]) -> Vec<Plugin> {
    let mut catalog = plugins.to_vec();
    catalog.extend([
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
                    previous.arguments.clone(),
                )?;
                if previous.plugin == crate::analysis::BROWSER {
                    run.message = BROWSER_RECOVERY_PENDING.into();
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
            (os.accepts(&plugin.id)
                && (plugin.id != crate::analysis::BROWSER
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
        let registry = ordinary.selected.remove(REGISTRY_ALL);
        for id in [crate::analysis::BROWSER, REGISTRY_ALL] {
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
