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

/// The common investigation tasks shown before the full plugin catalog.
pub fn basic_label(id: &str) -> Option<&'static str> {
    Some(match id {
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

/// Queue fresh attempts together, preserving the original runs and their options.
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
            if crate::investigation::is_native(&previous.plugin) {
                return crate::investigation::prepare(
                    evidence,
                    &previous.plugin,
                    previous.arguments.clone(),
                );
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
    case.queue_batch(runs)?;
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
            os.accepts(&plugin.id)
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
