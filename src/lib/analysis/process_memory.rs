//! Validated process-dump ranges shared by application parsers.
use crate::volatility::{Record, Table};

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
) -> Result<(Vec<Region>, usize), String> {
    let user_end = if table
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
