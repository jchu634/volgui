//! Resolve scan addresses into readable process-dump coordinates.
use std::path::{Path, PathBuf};

use crate::{
    case::{CaseSnapshot, RunStatus},
    extracted_files::open_artifact,
    results::{ResultStore, StoredRecord},
    volatility::Record,
};

pub const MEMMAP: &str = "windows.memmap.Memmap";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    Physical { pid: u64, offset: u64 },
    Virtual { pid: u64, offset: u64 },
}

fn number(record: &Record, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        let value = record.fields.get(*name)?;
        value.as_u64().or_else(|| {
            let value = value.as_str()?.trim();
            value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .map(|value| u64::from_str_radix(value, 16).ok())
                .unwrap_or_else(|| value.parse().ok())
        })
    })
}

impl Address {
    pub fn from_record(plugin: &str, record: &Record) -> Option<Self> {
        let pid = number(record, &["PID", "Pid", "ProcessID"])?;
        if let Some(offset) = number(record, &["Offset(P)", "Offset(Physical)"]) {
            return Some(Self::Physical { pid, offset });
        }
        let offset =
            number(record, &["Offset(V)", "Offset(Virtual)", "Virtual address"]).or_else(|| {
                if plugin.ends_with("malfind.Malfind") {
                    number(record, &["Start VPN"])
                } else if plugin.ends_with("vadyarascan.VadYaraScan") {
                    number(record, &["Offset"])
                } else {
                    None
                }
            })?;
        Some(Self::Virtual { pid, offset })
    }
}

pub enum Content {
    Ready(PathBuf, u64),
    NeedsDump { evidence_id: String, pid: u64 },
}

/// Addresses must be translated through Memmap, never used as file offsets.
/// Runs from other captures and mappings outside the saved dump are ineligible.
pub fn content(
    directory: &Path,
    document: &CaseSnapshot,
    selected: &StoredRecord,
) -> Result<Content, String> {
    let source = document
        .runs
        .iter()
        .find(|run| run.id == selected.run_id)
        .ok_or("Missing source analysis")?;
    let address = Address::from_record(&source.plugin, &selected.record)
        .ok_or("This result has no supported memory address to inspect.")?;
    let (pid, offset, field) = match address {
        Address::Physical { pid, offset } => (pid, offset, "Physical"),
        Address::Virtual { pid, offset } => (pid, offset, "Virtual"),
    };
    let store = ResultStore::at(directory);
    let filename = format!("pid.{pid}.dmp");
    let mut had_dump = false;
    for run in document.runs.iter().rev().filter(|run| {
        run.evidence_id == source.evidence_id
            && run.plugin == MEMMAP
            && run.status == RunStatus::Completed
            && run
                .arguments
                .windows(2)
                .any(|args| args[0] == "--pid" && args[1] == pid.to_string())
            && run.arguments.iter().any(|arg| arg == "--dump")
            && !run.arguments.iter().any(|arg| arg == "--user-memory")
    }) {
        had_dump = true;
        let path = directory.join("analyses").join(&run.id).join(&filename);
        let Ok(file) = open_artifact(&path) else {
            continue;
        };
        let total = file.metadata().map_err(|error| error.to_string())?.len();
        for row in store.table(&run.id)?.rows {
            if row.text("File output") != filename {
                continue;
            }
            let (Some(start), Some(size), Some(file)) = (
                number(&row, &[field]),
                number(&row, &["Size"]),
                number(&row, &["Offset in File"]),
            ) else {
                continue;
            };
            // Intel Memmap rows may omit the upper sign-extension bits.
            let mapped_offset = if field == "Virtual"
                && offset >= 0xffff_8000_0000_0000
                && (0x8000_0000_0000..0x1_0000_0000_0000).contains(&start)
            {
                offset & 0xffff_ffff_ffff
            } else {
                offset
            };
            if let Some(delta) = mapped_offset.checked_sub(start)
                && delta < size
                && start.checked_add(size).is_some()
                && file.checked_add(size).is_some_and(|end| end <= total)
            {
                return Ok(Content::Ready(path, file + delta));
            }
        }
    }
    if had_dump {
        return Err(format!(
            "Address {offset:#x} is unavailable in the collected memory for PID {pid}."
        ));
    }
    Ok(Content::NeedsDump {
        evidence_id: source.evidence_id.clone(),
        pid,
    })
}
