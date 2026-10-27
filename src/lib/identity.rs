//! Conservative, rebuildable associations. Findings and run rows never change.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicBool, Ordering},
};

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{case::Result, volatility::Record};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ProcessIdentity {
    pub role: String,
    os: String,
    pid: Option<String>,
    birth: Option<String>,
    addresses: BTreeMap<String, String>,
    name: Option<String>,
}

pub(super) fn number(row: &Record, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        let value = row.fields.get(*field)?;
        if let Some(value) = value.as_u64() {
            return Some(value.to_string());
        }
        let value = value.as_str()?.trim();
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map(|value| u64::from_str_radix(value, 16))
            .unwrap_or_else(|| value.parse::<u64>())
            .ok()
            .map(|value| value.to_string())
    })
}

/// Only labelled file-object addresses establish shared file identity. Unlabelled
/// FileScan offsets and path equality are deliberately insufficient.
pub(super) fn file_key(plugin: &str, row: &Record) -> Option<String> {
    let (space, address) = match plugin {
        "windows.filescan.FileScan" => {
            if let Some(address) = number(row, &["Offset(V)"]) {
                ("virtual", address)
            } else {
                ("physical", number(row, &["Offset(P)"])?)
            }
        }
        "windows.handles.Handles" if row.text("Type") == "File" => {
            ("virtual", number(row, &["Offset(V)", "Offset"])?)
        }
        _ => return None,
    };
    (address != "0").then(|| format!("file:windows:{space}:{address}"))
}

pub(super) fn describe(plugin: &str, row: &Record) -> ProcessIdentity {
    let parts: Vec<_> = plugin.split('.').collect();
    let family = parts
        .get(parts.len().saturating_sub(2))
        .copied()
        .unwrap_or("");
    let os = parts.first().copied().unwrap_or("");
    let role = if !row.is_partial_match() && matches!(os, "windows" | "linux" | "mac") {
        match family {
            "pslist" | "psscan" | "pstree" | "psaux" => "inventory",
            "cmdline" => "command",
            "handles" => "handle",
            _ => "none",
        }
    } else {
        "none"
    };
    let birth_fields: &[&str] = if role == "handle" {
        &["ProcessCreateTime", "ProcessCreationTime"]
    } else {
        &[
            "CreateTime",
            "CreationTime",
            "StartTime",
            "ProcessCreateTime",
        ]
    };
    let birth = birth_fields.iter().find_map(|field| {
        let value = row.fields.get(*field)?;
        if let Some(value) = value.as_u64().filter(|value| *value > 0) {
            return Some(value.to_string());
        }
        let value = value.as_str()?.trim();
        // Unknown/unreadable markers cannot serve as process identities.
        if let Ok(value) = value.parse::<u64>() {
            return (value > 0).then(|| value.to_string());
        }
        let time = chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .or_else(|| chrono::DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%:z").ok())
            .map(|value| value.with_timezone(&chrono::Utc))
            .or_else(|| {
                chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f UTC")
                    .ok()
                    .map(|value| value.and_utc())
            });
        time.filter(|time| time.timestamp() > 0)
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
    });
    let mut addresses = BTreeMap::new();
    let address_fields: &[(&str, &[&str])] = if role == "handle" {
        &[("virtual", &["EPROCESS", "ProcessOffset(V)"])]
    } else {
        &[
            ("virtual", &["Offset(V)", "EPROCESS", "Task"]),
            ("physical", &["Offset(P)"]),
        ]
    };
    for (space, fields) in address_fields {
        if let Some(address) = number(row, fields).filter(|address| address != "0") {
            addresses.insert((*space).to_owned(), address);
        }
    }
    let name = ["ImageFileName", "COMM", "Process"]
        .iter()
        .find_map(|field| {
            row.fields
                .get(*field)?
                .as_str()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_ascii_lowercase)
        });
    ProcessIdentity {
        role: role.into(),
        os: os.into(),
        pid: number(row, &["PID", "Pid", "pid"]),
        birth,
        addresses,
        name,
    }
}

impl ProcessIdentity {
    fn strong(&self) -> bool {
        self.birth.is_some() || !self.addresses.is_empty()
    }

    fn compatible(&self, other: &Self) -> bool {
        self.os == other.os
            && self.pid == other.pid
            && !matches!((&self.birth, &other.birth), (Some(a), Some(b)) if a != b)
            && self.addresses.iter().all(|(space, address)| {
                other
                    .addresses
                    .get(space)
                    .is_none_or(|other| other == address)
            })
    }

    fn shares_key(&self, other: &Self) -> bool {
        matches!((&self.birth, &other.birth), (Some(a), Some(b)) if a == b)
            || self
                .addresses
                .iter()
                .any(|(space, address)| other.addresses.get(space) == Some(address))
    }
}

struct Finding {
    observation: i64,
    entity: i64,
    ppid: Option<String>,
    identity: ProcessIdentity,
}

struct Group {
    entity: i64,
    signature: ProcessIdentity,
    members: Vec<usize>,
    names: BTreeSet<String>,
    inventory: bool,
}

impl Group {
    fn new(index: usize, finding: &Finding) -> Self {
        Self {
            entity: finding.entity,
            signature: finding.identity.clone(),
            members: vec![index],
            names: finding.identity.name.iter().cloned().collect(),
            inventory: finding.identity.role == "inventory",
        }
    }

    fn add(&mut self, index: usize, finding: &Finding) {
        self.members.push(index);
        self.entity = self.entity.min(finding.entity);
        self.inventory |= finding.identity.role == "inventory";
        if self.signature.birth.is_none() {
            self.signature.birth = finding.identity.birth.clone();
        }
        self.signature
            .addresses
            .extend(finding.identity.addresses.clone());
        self.names.extend(finding.identity.name.iter().cloned());
    }

    fn weak_name_matches(&self, identity: &ProcessIdentity) -> bool {
        identity
            .name
            .as_ref()
            .is_none_or(|name| self.names.iter().all(|other| other == name))
    }
}

/// Recompute uncertain links when later inventories expose PID reuse. Entity rows
/// remain valid; only derived memberships and relations can change.
pub(super) fn reconcile(
    db: &rusqlite::Transaction<'_>,
    evidence: &str,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut statement = db
        .prepare(
            "SELECT id,base_entity_id,ppid,process_identity_json FROM observations
         WHERE evidence_id=?1 AND process_role!='none' ORDER BY id",
        )
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([evidence], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut findings = Vec::new();
    for row in rows {
        let (observation, entity, ppid, json) = row.map_err(|e| e.to_string())?;
        findings.push(Finding {
            observation,
            entity,
            ppid,
            identity: serde_json::from_str(&json).map_err(|e| e.to_string())?,
        });
    }
    if findings.is_empty() {
        return Ok(());
    }
    let mut by_pid = BTreeMap::<(String, String), Vec<usize>>::new();
    for (index, finding) in findings.iter().enumerate() {
        if let Some(pid) = &finding.identity.pid {
            by_pid
                .entry((finding.identity.os.clone(), pid.clone()))
                .or_default()
                .push(index);
        }
    }
    db.execute(
        "DELETE FROM entity_relations WHERE observation_id IN
        (SELECT id FROM observations WHERE evidence_id=?1)",
        [evidence],
    )
    .map_err(|e| e.to_string())?;
    let mut membership = db
        .prepare_cached("UPDATE observation_entities SET entity_id=?1 WHERE observation_id=?2")
        .map_err(|e| e.to_string())?;
    for finding in &findings {
        membership
            .execute(params![finding.entity, finding.observation])
            .map_err(|e| e.to_string())?;
    }
    let mut unique_inventory = BTreeMap::<(String, String), Group>::new();
    for (key, indices) in by_pid {
        if cancel.load(Ordering::Relaxed) {
            return Err("Saving scan cancelled".into());
        }
        let mut strong: Vec<_> = indices
            .iter()
            .copied()
            .filter(|index| {
                let identity = &findings[*index].identity;
                identity.role != "handle" && identity.strong()
            })
            .collect();
        // Most specific records establish groups before records missing a key.
        strong.sort_by_key(|index| {
            let identity = &findings[*index].identity;
            (
                std::cmp::Reverse(usize::from(identity.birth.is_some()) + identity.addresses.len()),
                std::cmp::Reverse(identity.birth.is_some()),
                findings[*index].observation,
            )
        });
        let mut groups = Vec::<Group>::new();
        for index in strong {
            let identity = &findings[index].identity;
            let candidates: Vec<_> = groups
                .iter()
                .enumerate()
                .filter(|(_, group)| {
                    group.signature.compatible(identity) && group.signature.shares_key(identity)
                })
                .map(|(index, _)| index)
                .collect();
            if let [group] = candidates.as_slice() {
                groups[*group].add(index, &findings[index]);
            } else {
                groups.push(Group::new(index, &findings[index]));
            }
        }
        // Inventory rows with only a PID are independent anchors unless exactly
        // one stronger identity explains them. Names only reject, never identify.
        for index in indices.iter().copied().filter(|index| {
            findings[*index].identity.role == "inventory" && !findings[*index].identity.strong()
        }) {
            if groups.len() == 1
                && groups[0].signature.strong()
                && groups[0].weak_name_matches(&findings[index].identity)
            {
                groups[0].add(index, &findings[index]);
            } else {
                groups.push(Group::new(index, &findings[index]));
            }
        }
        // Resolve commands only against a single inventory identity. More than
        // one identity for this PID leaves PID-only command lines unassigned.
        if groups.len() == 1 && groups[0].inventory {
            for index in indices.iter().copied().filter(|index| {
                findings[*index].identity.role == "command" && !findings[*index].identity.strong()
            }) {
                if groups[0].weak_name_matches(&findings[index].identity) {
                    groups[0].add(index, &findings[index]);
                }
            }
        }
        for group in &groups {
            for index in &group.members {
                membership
                    .execute(params![group.entity, findings[*index].observation])
                    .map_err(|e| e.to_string())?;
            }
        }
        if groups.len() == 1 && groups[0].inventory {
            unique_inventory.insert(key, groups.remove(0));
        }
    }
    let mut relation = db.prepare_cached("INSERT OR IGNORE INTO entity_relations(subject,predicate,object,observation_id) VALUES(?1,?2,?3,?4)")
        .map_err(|e| e.to_string())?;
    for (index, finding) in findings.iter().enumerate() {
        if index % 256 == 0 && cancel.load(Ordering::Relaxed) {
            return Err("Saving scan cancelled".into());
        }
        if finding.identity.role != "handle" {
            continue;
        }
        let Some(pid) = &finding.identity.pid else {
            continue;
        };
        if let Some(owner) = unique_inventory.get(&(finding.identity.os.clone(), pid.clone()))
            && owner.signature.compatible(&finding.identity)
            && owner.weak_name_matches(&finding.identity)
        {
            relation
                .execute(params![
                    owner.entity,
                    "owns_handle",
                    finding.entity,
                    finding.observation
                ])
                .map_err(|e| e.to_string())?;
        }
    }
    for ((os, pid), group) in &unique_inventory {
        let parents: BTreeSet<_> = group
            .members
            .iter()
            .filter_map(|index| findings[*index].ppid.as_ref())
            .collect();
        let Some(ppid) = parents.first().filter(|_| parents.len() == 1) else {
            continue;
        };
        if *ppid == pid {
            continue;
        }
        if let Some(parent) = unique_inventory.get(&(os.clone(), (*ppid).clone())) {
            // When both timestamps parse, a parent born after its child cannot
            // be the parent process referenced by this PPID.
            if let (Some(parent_birth), Some(child_birth)) =
                (&parent.signature.birth, &group.signature.birth)
                && let (Some(parent_time), Some(child_time)) =
                    (timestamp(parent_birth), timestamp(child_birth))
                && parent_time > child_time
            {
                continue;
            }
            for index in group
                .members
                .iter()
                .filter(|index| findings[**index].ppid.as_ref() == Some(*ppid))
            {
                relation
                    .execute(params![
                        parent.entity,
                        "parent_of",
                        group.entity,
                        findings[*index].observation
                    ])
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn timestamp(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.timestamp())
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f UTC")
                .ok()
                .map(|value| value.and_utc().timestamp())
        })
}
