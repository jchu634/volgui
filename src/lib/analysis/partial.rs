//! Shared record metadata and independent limits for parser-specific fallbacks.
use crate::volatility::Record;

pub(super) fn mark(row: &mut Record, kind: &str, failures: &[&str]) {
    debug_assert!(!failures.is_empty());
    row.fields.insert("Partial match".into(), true.into());
    row.fields.insert("Partial match kind".into(), kind.into());
    row.fields
        .insert("Validation failures".into(), failures.join("; ").into());
}

/// Returns which classes overflowed. Extra partials never consume strict slots.
pub(super) fn bound(
    rows: &mut Vec<Record>,
    strict_limit: usize,
    partial_limit: usize,
) -> (bool, bool) {
    let (mut strict, mut partial) = (0, 0);
    rows.retain(|row| {
        let (count, limit) = if row.is_partial_match() {
            (&mut partial, partial_limit)
        } else {
            (&mut strict, strict_limit)
        };
        *count += 1;
        *count <= limit
    });
    (strict > strict_limit, partial > partial_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::record;
    use serde_json::json;

    #[test]
    fn partial_flood_does_not_displace_later_strict_findings() {
        let mut rows: Vec<_> = (0..100)
            .map(|n| {
                let mut row = record(json!({"Name":n}));
                mark(&mut row, "Test", &["Missing corroboration"]);
                row
            })
            .collect();
        rows.extend([
            record(json!({"Name":"strict"})),
            record(json!({"Name":"extra"})),
        ]);
        assert_eq!(bound(&mut rows, 1, 2), (true, true));
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].text("Name"), "strict");
        assert_eq!(rows[0].text("Validation failures"), "Missing corroboration");
    }
}
