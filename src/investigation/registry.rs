use crate::{
    case::{Case, Run, RunStatus},
    volatility::{Installation, Record},
};
pub const PRINT_KEY: &str = "windows.registry.printkey.PrintKey";

pub fn hive_offset(record: &Record) -> Option<u64> {
    ["Hive Offset", "Offset", "Offset(V)", "Offset(P)"]
        .iter()
        .find_map(|name| {
            let value = record.fields.get(*name)?;
            value.as_u64().or_else(|| {
                let text = value.as_str()?.trim();
                text.strip_prefix("0x")
                    .or_else(|| text.strip_prefix("0X"))
                    .map_or_else(|| text.parse().ok(), |s| u64::from_str_radix(s, 16).ok())
            })
        })
        .filter(|offset| *offset != 0)
}

pub fn prepare(
    case: &Case,
    engine: &Installation,
    source: &Run,
    record: &Record,
    key: &str,
    recurse: bool,
) -> Result<Run, String> {
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == source.evidence_id)
        .ok_or("Source evidence is no longer available")?;
    engine.prepare(
        evidence,
        PRINT_KEY,
        arguments(record, key, recurse)?,
        &case.directory.join("analyses"),
    )
}

pub fn arguments(record: &Record, key: &str, recurse: bool) -> Result<Vec<String>, String> {
    let offset = hive_offset(record)
        .ok_or("Select a registry hive or a PrintKey record with a hive offset")?;
    let mut arguments = vec!["--offset".into(), format!("{offset:#x}")];
    if !key.is_empty() {
        arguments.extend(["--key".into(), key.into()]);
    }
    if recurse {
        arguments.push("--recurse".into());
    }
    Ok(arguments)
}

pub fn cached<'a>(case: &'a Case, source: &Run, arguments: &[String]) -> Option<&'a Run> {
    case.document.runs.iter().rev().find(|r| {
        r.evidence_id == source.evidence_id
            && r.plugin == PRINT_KEY
            && r.arguments == arguments
            && r.status == RunStatus::Completed
    })
}

/// PrintKey includes the hive's display name at the start of Key, while --key is relative.
pub fn child_key(source: &Run, record: &Record) -> Option<String> {
    if source.plugin != PRINT_KEY
        || record.text("Type") != "Key"
        || source.arguments.iter().any(|a| a == "--recurse")
    {
        return None;
    }
    let parent = source
        .arguments
        .windows(2)
        .find(|p| p[0] == "--key")
        .map(|p| p[1].trim_matches('\\'))
        .unwrap_or("");
    let name = record.text("Name");
    if name.is_empty() || name.contains('\\') {
        return None;
    }
    Some(if parent.is_empty() {
        name
    } else {
        format!("{parent}\\{name}")
    })
}
