//! Validated process-dump ranges shared by application parsers.
use crate::volatility::{Record, Table};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DumpScope {
    Full,
    User,
}

impl DumpScope {
    pub fn arguments(self, pid: u64) -> Vec<String> {
        let mut args = vec!["--pid".into(), pid.to_string(), "--dump".into()];
        if self == Self::User {
            args.push("--user-memory".into());
        }
        args
    }

    pub fn from_arguments(args: &[String], pid: u64) -> Option<Self> {
        [Self::Full, Self::User]
            .into_iter()
            .find(|scope| args == scope.arguments(pid))
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Region {
    pub file: u64,
    pub virtual_start: u64,
    pub length: u64,
}

pub(super) fn number(row: &Record, field: &str) -> Option<u64> {
    let value = row.fields.get(field)?;
    value.as_u64().or_else(|| {
        let text = value.as_str()?;
        text.strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .map(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or_else(|| text.parse().ok())
    })
}

pub(super) fn regions(
    table: Table,
    filename: &str,
    total: u64,
    scope: DumpScope,
) -> Result<(Vec<Region>, usize), String> {
    let explicit_limits: Vec<_> = table
        .rows
        .iter()
        .filter(|row| row.text("File output") == filename)
        .map(|row| number(row, "User address limit"))
        .collect();
    let explicit = explicit_limits.iter().any(Option::is_some);
    let user_end = if explicit || scope == DumpScope::User {
        let limit = explicit_limits
            .first()
            .copied()
            .flatten()
            .ok_or("User-memory dump is missing its user address limit")?;
        if !(limit == 1 << 47
            || (0x8000_0000..=0xc000_0000).contains(&limit) && limit.is_multiple_of(4096))
            || explicit_limits.iter().any(|value| *value != Some(limit))
        {
            return Err("User-memory dump has invalid or inconsistent user address limits".into());
        }
        limit
    } else if table
        .rows
        .iter()
        .any(|row| number(row, "Virtual").is_some_and(|v| v > u64::from(u32::MAX)))
    {
        1 << 47
    } else {
        1 << 31
    };
    let mut ranges = Vec::new();
    let mut rejected = 0;
    for row in table
        .rows
        .iter()
        .filter(|r| r.text("File output") == filename)
    {
        let (Some(file), Some(virtual_start), Some(length)) = (
            number(row, "Offset in File"),
            number(row, "Virtual"),
            number(row, "Size"),
        ) else {
            rejected += 1;
            continue;
        };
        // Includes Intel mappings whose upper sign-extension bits were masked.
        if virtual_start >= user_end {
            continue;
        }
        if length == 0
            || file.checked_add(length).is_none_or(|end| end > total)
            || virtual_start
                .checked_add(length)
                .is_none_or(|end| end > user_end)
        {
            rejected += 1;
            continue;
        }
        ranges.push(Region {
            file,
            virtual_start,
            length,
        });
    }
    ranges.sort_by_key(|r| r.file);
    let mut merged: Vec<Region> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if last.file + last.length > range.file {
                rejected += 1;
                continue;
            }
            if last.file + last.length == range.file
                && last.virtual_start + last.length == range.virtual_start
            {
                last.length += range.length;
                continue;
            }
        }
        merged.push(range);
    }
    if merged.is_empty() {
        return Err(format!(
            "No readable Memmap ranges for this PID; rejected {rejected} invalid ranges"
        ));
    }
    Ok((merged, rejected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicit_user_limit_keeps_low_x64_and_three_gigabyte_mappings() {
        for limit in [1u64 << 47, 0xc000_0000] {
            let table = Table::parse(
                &json!([
                    {"File output":"pid.42.dmp", "Virtual":0x9000_0000u64,
                     "Size":4096,"Offset in File":0,"User address limit":limit},
                    {"File output":"pid.42.dmp", "Virtual":limit,
                     "Size":4096,"Offset in File":4096,"User address limit":limit}
                ])
                .to_string(),
            )
            .unwrap();
            let (ranges, rejected) = regions(table, "pid.42.dmp", 8192, DumpScope::User).unwrap();
            assert_eq!(ranges.len(), 1);
            assert_eq!(ranges[0].virtual_start, 0x9000_0000);
            assert_eq!(rejected, 0);
        }
    }

    #[test]
    fn scoped_dumps_require_consistent_bounded_metadata() {
        let row = json!({"File output":"pid.42.dmp", "Virtual":4096,
            "Size":4096,"Offset in File":0});
        for limit in [None, Some(0), Some(u64::MAX), Some(0xc000_0001)] {
            let mut row = row.clone();
            if let Some(limit) = limit {
                row["User address limit"] = json!(limit);
            }
            let table = Table::parse(&json!([row]).to_string()).unwrap();
            assert!(regions(table, "pid.42.dmp", 4096, DumpScope::User).is_err());
        }
        let mut a = row.clone();
        a["User address limit"] = json!(1u64 << 47);
        let mut b = row;
        b["User address limit"] = json!(1u64 << 31);
        let table = Table::parse(&json!([a, b]).to_string()).unwrap();
        assert!(regions(table, "pid.42.dmp", 8192, DumpScope::User).is_err());
    }

    #[test]
    fn reuse_accepts_only_complete_known_dump_scopes_for_the_requested_pid() {
        for scope in [DumpScope::Full, DumpScope::User] {
            assert_eq!(
                DumpScope::from_arguments(&scope.arguments(42), 42),
                Some(scope)
            );
            assert_eq!(DumpScope::from_arguments(&scope.arguments(42), 43), None);
            let mut filtered = scope.arguments(42);
            filtered.extend(["--address".into(), "4096".into()]);
            assert_eq!(DumpScope::from_arguments(&filtered, 42), None);
        }
    }
}
