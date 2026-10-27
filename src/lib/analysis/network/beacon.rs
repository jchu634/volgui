//! Conservative stock Cobalt Strike HTTP(S) TLV configuration recovery.
//! Format reference: https://github.com/fox-it/dissect.cobaltstrike/blob/main/dissect/cobaltstrike/beacon.py
use super::super::record;
use crate::volatility::Record;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::OnceLock};

pub(in crate::analysis) const FAMILY: &str = "Cobalt Strike Beacon";
const HEADER: [u8; 7] = [0, 1, 0, 1, 0, 2, 0];
const KEYS: [u8; 3] = [0, 0x2e, 0x69];
pub(in crate::analysis) const MAX_PARTIAL_FINDINGS: usize = 200;
pub(in crate::analysis) fn discovery_pattern() -> String {
    // Every configuration accepted by parse starts with protocol 0 or 8 and
    // another typed TLV. Seven header bytes alone also match common data tables.
    let byte = |b: u8, key: u8| format!("\\x{:02x}", b ^ key);
    let alternatives = |values: &[u8], key: u8| {
        let mut values: Vec<u8> = values.iter().map(|b| b ^ key).collect();
        values.sort_unstable();
        values.dedup();
        let mut class = String::from("[");
        let mut i = 0;
        while i < values.len() {
            let first = values[i];
            let mut last = first;
            i += 1;
            while i < values.len() && last.checked_add(1) == Some(values[i]) {
                last = values[i];
                i += 1;
            }
            class.push_str(&byte(first, 0));
            if first != last {
                class.push('-');
                class.push_str(&byte(last, 0));
            }
        }
        class.push(']');
        class
    };
    KEYS.iter()
        .map(|key| {
            let header = HEADER
                .iter()
                .map(|b| format!("\\x{:02x}", b ^ key))
                .collect::<String>();
            let typed = [
                [0, 1, 0, 2].map(|b| byte(b, *key)).concat(),
                [0, 2, 0, 4].map(|b| byte(b, *key)).concat(),
                // Pointer/string TLVs have a nonzero length no larger than 2048.
                format!(
                    "{}(?:{}{}|{}{}|{}{})",
                    [0, 3].map(|b| byte(b, *key)).concat(),
                    byte(0, *key),
                    alternatives(&(1..=255).collect::<Vec<_>>(), *key),
                    alternatives(&(1..=7).collect::<Vec<_>>(), *key),
                    r"[\s\S]",
                    byte(8, *key),
                    byte(0, *key)
                ),
            ]
            .join("|");
            format!(
                "(?-iu:{header}{}{}{}(?:{typed}))",
                alternatives(&[0, 8], *key),
                byte(0, *key),
                alternatives(&(1..=127).collect::<Vec<_>>(), *key)
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}
fn string(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|b| *b == 0)?;
    if bytes[end..].iter().any(|b| *b != 0) {
        return None;
    }
    let value = std::str::from_utf8(&bytes[..end]).ok()?;
    value
        .bytes()
        .all(|b| b.is_ascii_graphic() || b == b' ')
        .then_some(value)
}
fn der<'a>(bytes: &'a [u8], at: &mut usize, tag: u8) -> Option<&'a [u8]> {
    if *bytes.get(*at)? != tag {
        return None;
    }
    *at += 1;
    let lead = *bytes.get(*at)?;
    *at += 1;
    let length = if lead & 0x80 == 0 {
        usize::from(lead)
    } else {
        let count = usize::from(lead & 0x7f);
        if count == 0 || count > 2 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = length
                .checked_mul(256)?
                .checked_add(usize::from(*bytes.get(*at)?))?;
            *at += 1;
        }
        length
    };
    let end = at.checked_add(length)?;
    let body = bytes.get(*at..end)?;
    *at = end;
    Some(body)
}
fn rsa_public_key(bytes: &[u8]) -> bool {
    let valid = || -> Option<()> {
        let mut at = 0;
        let body = der(bytes, &mut at, 0x30)?;
        if bytes[at..].iter().any(|b| *b != 0) {
            return None;
        }
        let mut at = 0;
        let algorithm = der(body, &mut at, 0x30)?;
        if algorithm
            != [
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
            ]
        {
            return None;
        }
        let bits = der(body, &mut at, 0x03)?;
        if at != body.len() || bits.first() != Some(&0) {
            return None;
        }
        let mut at = 0;
        let rsa = der(&bits[1..], &mut at, 0x30)?;
        if at != bits.len() - 1 {
            return None;
        }
        let mut at = 0;
        let modulus = der(rsa, &mut at, 0x02)?;
        let exponent = der(rsa, &mut at, 0x02)?;
        if at != rsa.len()
            || !(64..=513).contains(&modulus.len())
            || modulus[0] & 0x80 != 0
            || modulus.iter().all(|b| *b == 0)
            || exponent.is_empty()
            || exponent.len() > 4
            || exponent[0] & 0x80 != 0
        {
            return None;
        }
        let value = exponent.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b));
        if value < 3 || value.is_multiple_of(2) {
            return None;
        }
        Some(())
    };
    valid().is_some()
}
fn parse(bytes: &[u8], key: u8) -> Option<Vec<Record>> {
    let decoded: Vec<_> = bytes.iter().take(6144).map(|b| b ^ key).collect();
    if !decoded.starts_with(&HEADER) {
        return None;
    }
    let mut fields = BTreeMap::new();
    let mut at = 0usize;
    loop {
        let id = u16::from_be_bytes(decoded.get(at..at + 2)?.try_into().ok()?);
        if id == 0 {
            break;
        }
        let kind = u16::from_be_bytes(decoded.get(at + 2..at + 4)?.try_into().ok()?);
        let length = u16::from_be_bytes(decoded.get(at + 4..at + 6)?.try_into().ok()?) as usize;
        if id > 127
            || length == 0
            || length > 2048
            || !(kind == 1 && length == 2 || kind == 2 && length == 4 || kind == 3)
        {
            return None;
        }
        let value = decoded.get(at + 6..at + 6 + length)?;
        if fields.insert(id, (kind, value)).is_some() {
            return None;
        }
        at += 6 + length;
        if fields.len() > 127 {
            return None;
        }
    }
    if decoded.get(at..at + 66)?.iter().any(|b| *b != 0) {
        return None;
    }
    let short = |id| {
        let (kind, value) = fields.get(&id)?;
        if *kind != 1 {
            return None;
        }
        Some(u16::from_be_bytes((*value).try_into().ok()?))
    };
    // Avoid accepting a protocol marker alone: require coherent typed settings,
    // a structured RSA public key and valid domain/URI pairs.
    let protocol = short(1)?;
    if ![0, 8].contains(&protocol) {
        return None;
    }
    let port = short(2)?;
    if port == 0 || short(5)? > 100 {
        return None;
    }
    let integer = |id| {
        let (kind, value) = fields.get(&id)?;
        if *kind != 2 {
            return None;
        }
        Some(u32::from_be_bytes((*value).try_into().ok()?))
    };
    let sleep = integer(3)?;
    let max_get = integer(4)?;
    if sleep > 30 * 86400 * 1000 || max_get == 0 || max_get > 16 * 1024 * 1024 {
        return None;
    }
    let pointer = |id| {
        let (kind, value) = fields.get(&id)?;
        (*kind == 3).then_some(*value)
    };
    let public_key = pointer(7)?;
    if !rsa_public_key(public_key) {
        return None;
    }
    let domains = string(pointer(8)?)?;
    let agent = string(pointer(9)?)?;
    let submit = string(pointer(10)?)?;
    if agent.is_empty() || !submit.starts_with('/') || submit.contains(' ') {
        return None;
    }
    let pairs: Vec<_> = domains.split(',').collect();
    if pairs.is_empty() || !pairs.len().is_multiple_of(2) || pairs.len() > 128 {
        return None;
    }
    let hash = format!("{:x}", Sha256::digest(&decoded[..at + 2]));
    let mut rows = Vec::new();
    for pair in pairs.chunks_exact(2) {
        if !pair[1].starts_with('/') || pair[1].bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        let (field, host) = super::commands::target(pair[0], port)?;
        let mut row = record(
            json!({"Finding":"Cobalt Strike Beacon configuration","Program":FAMILY,"Port":port,"Protocol":if protocol==8{"HTTPS"}else{"HTTP"},
            "URI path":pair[1],"Submit URI":submit,"User agent":agent,"Sleep milliseconds":sleep,"Jitter percent":short(5)?,
            "Configuration bytes SHA-256":hash,"Encoded bytes SHA-256":format!("{:x}",Sha256::digest(&bytes[..at+2])),"Configuration byte length":at+2,"XOR key":format!("0x{key:02x}"),
            "Validation":"Stock big-endian typed settings, zero terminator/padding, protocol/port/timeouts, RSA public key structure and domain/URI pairs validated; configuration slot size and Beacon version are not inferred",
            "Interpretation":"A stock Cobalt Strike Beacon HTTP(S) configuration names this target. This does not establish execution, an owning process or a successful connection."}),
        );
        row.fields.insert(field, host.into());
        rows.push(row);
    }
    Some(rows)
}

fn parse_partial(bytes: &[u8], key: u8) -> Option<Vec<Record>> {
    let decoded: Vec<_> = bytes.iter().take(6144).map(|b| b ^ key).collect();
    if !decoded.starts_with(&HEADER) {
        return None;
    }
    let mut fields = BTreeMap::new();
    let mut at = 0usize;
    let mut failures = Vec::new();
    loop {
        let Some(header) = decoded.get(at..at + 2) else {
            failures.push("Configuration terminator is missing");
            break;
        };
        let id = u16::from_be_bytes(header.try_into().ok()?);
        if id == 0 {
            if decoded
                .get(at..at + 66)
                .is_none_or(|padding| padding.iter().any(|b| *b != 0))
            {
                failures.push("Terminator padding is missing or damaged");
            }
            at += 2;
            break;
        }
        let Some(header) = decoded.get(at..at + 6) else {
            failures.push("Trailing setting header is truncated");
            break;
        };
        let kind = u16::from_be_bytes(header[2..4].try_into().ok()?);
        let length = u16::from_be_bytes(header[4..6].try_into().ok()?) as usize;
        if id > 127
            || length == 0
            || length > 2048
            || !(kind == 1 && length == 2 || kind == 2 && length == 4 || kind == 3)
        {
            failures.push("Trailing setting has invalid type, identifier or length");
            break;
        }
        // Duplicate IDs undermine the interpretation of the surviving settings.
        if fields.contains_key(&id) {
            return None;
        }
        let Some(value) = decoded.get(at + 6..at + 6 + length) else {
            failures.push("Trailing setting value is truncated");
            break;
        };
        fields.insert(id, (kind, value));
        at += 6 + length;
    }
    let short = |id| -> Option<u16> {
        let (kind, value) = fields.get(&id)?;
        (*kind == 1).then_some(())?;
        Some(u16::from_be_bytes((*value).try_into().ok()?))
    };
    let integer = |id| -> Option<u32> {
        let (kind, value) = fields.get(&id)?;
        (*kind == 2).then_some(())?;
        Some(u32::from_be_bytes((*value).try_into().ok()?))
    };
    let pointer = |id| -> Option<&[u8]> {
        let (kind, value) = fields.get(&id)?;
        (*kind == 3).then_some(*value)
    };
    let protocol = short(1)?;
    let port = short(2)?;
    let sleep = integer(3)?;
    let max_get = integer(4)?;
    let jitter = short(5)?;
    if ![0, 8].contains(&protocol)
        || port == 0
        || sleep > 30 * 86400 * 1000
        || max_get == 0
        || max_get > 16 * 1024 * 1024
        || jitter > 100
    {
        return None;
    }
    let domains = string(pointer(8)?)?;
    let pairs: Vec<_> = domains.split(',').collect();
    if pairs.is_empty() || !pairs.len().is_multiple_of(2) || pairs.len() > 128 {
        return None;
    }
    let rsa = pointer(7).is_some_and(rsa_public_key);
    let agent = pointer(9).and_then(string).filter(|s| !s.is_empty());
    let submit = pointer(10)
        .and_then(string)
        .filter(|s| s.starts_with('/') && !s.contains(' '));
    // A typed prefix and host string alone are common in unrelated tables.
    // Keep either the RSA structure or both HTTP strings as independent anchors.
    if !rsa && (agent.is_none() || submit.is_none()) {
        return None;
    }
    if !rsa {
        failures.push("RSA public key is missing or invalid");
    }
    if agent.is_none() {
        failures.push("User agent is missing or invalid");
    }
    if submit.is_none() {
        failures.push("Submit URI is missing or invalid");
    }
    if failures.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    for pair in pairs.chunks_exact(2) {
        if !pair[1].starts_with('/') || pair[1].bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        let (field, host) = super::commands::target(pair[0], port)?;
        let mut row = record(json!({
            "Finding":"Partial Cobalt Strike Beacon configuration candidate", "Program":FAMILY,
            "Port":port, "Protocol":if protocol == 8 {"HTTPS"} else {"HTTP"},
            "URI path":pair[1], "Sleep milliseconds":sleep, "Jitter percent":jitter,
            "Configuration byte length":at, "XOR key":format!("0x{key:02x}"),
            "Candidate bytes SHA-256":format!("{:x}", Sha256::digest(&decoded[..at])),
            "Validation":"Coherent typed protocol, port, sleep, size and jitter settings, valid host/URI pairs, plus an RSA key or both HTTP request strings",
            "Interpretation":"Partially corroborated stock Beacon-like settings. Full configuration validation failed. This does not establish a Beacon payload, execution, process ownership or a successful connection."
        }));
        row.fields.insert(field, host.into());
        if let Some(agent) = agent {
            row.fields.insert("User agent".into(), agent.into());
        }
        if let Some(submit) = submit {
            row.fields.insert("Submit URI".into(), submit.into());
        }
        super::super::partial::mark(&mut row, "Beacon configuration", &failures);
        rows.push(row);
    }
    Some(rows)
}
/// Return local buffer offsets; callers supply acquisition or virtual coordinates.
pub(in crate::analysis) fn scan(
    bytes: &[u8],
    core: std::ops::Range<usize>,
) -> Vec<(usize, Record)> {
    static NEEDLES: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    let needles = NEEDLES.get_or_init(|| {
        KEYS.iter()
            .map(|key| HEADER.iter().map(|b| b ^ key).collect())
            .collect()
    });
    let mut rows = Vec::new();
    let mut partial_rows = Vec::new();
    for (key, needle) in KEYS.iter().zip(needles) {
        for at in memchr::memmem::find_iter(bytes, needle).filter(|at| core.contains(at)) {
            if let Some(found) = parse(&bytes[at..], *key) {
                rows.extend(found.into_iter().map(|row| (at, row)));
            } else if partial_rows.len() < MAX_PARTIAL_FINDINGS
                && let Some(found) = parse_partial(&bytes[at..], *key)
            {
                let remaining = MAX_PARTIAL_FINDINGS - partial_rows.len();
                partial_rows.extend(found.into_iter().take(remaining).map(|row| (at, row)));
            }
            if rows.len() >= super::MAX_FINDINGS {
                rows.extend(partial_rows);
                return rows;
            }
        }
    }
    rows.extend(partial_rows);
    rows
}

#[cfg(test)]
pub(in crate::analysis) mod tests {
    use super::*;
    #[test]
    fn discovery_validates_typed_prefix_for_each_encoding_and_retains_partial_leads() {
        let re = regex::bytes::Regex::new(&format!("(?-u)(?:{})", discovery_pattern())).unwrap();
        for key in KEYS {
            let bytes = fixture(key);
            assert!(re.is_match(&bytes));
            assert!(
                re.is_match(&bytes[..16]),
                "A structured but incomplete prefix remains a candidate"
            );
            let mut noise = vec![key; 32];
            for (i, byte) in HEADER.iter().enumerate() {
                noise[i] = byte ^ key;
            }
            assert!(
                !re.is_match(&noise),
                "Header-only tables must not select a process"
            );
        }
    }
    pub(in crate::analysis) fn fixture(key: u8) -> Vec<u8> {
        let mut b = Vec::new();
        let mut field = |id: u16, kind: u16, value: &[u8]| {
            b.extend(id.to_be_bytes());
            b.extend(kind.to_be_bytes());
            b.extend((value.len() as u16).to_be_bytes());
            b.extend(value);
        };
        field(1, 1, &8u16.to_be_bytes());
        field(2, 1, &443u16.to_be_bytes());
        field(3, 2, &60000u32.to_be_bytes());
        field(4, 2, &1048576u32.to_be_bytes());
        field(5, 1, &20u16.to_be_bytes());
        let mut public_key = vec![
            0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0,
        ];
        public_key.extend([0x81; 128]);
        public_key.extend([0x02, 0x03, 0x01, 0, 0x01]);
        field(7, 3, &public_key);
        field(8, 3, b"192.0.2.5,/a,example.test,/b\0");
        field(9, 3, b"Mozilla/5.0\0");
        field(10, 3, b"/submit\0");
        b.resize(4096, 0);
        b.iter_mut().for_each(|b| *b ^= key);
        b
    }
    pub(in crate::analysis) fn partial_fixture(key: u8) -> Vec<u8> {
        let mut bytes = fixture(0);
        // Keep all typed settings but remove the transport terminator/padding.
        let mut at = 0;
        while bytes[at..at + 2] != [0, 0] {
            let length = u16::from_be_bytes(bytes[at + 4..at + 6].try_into().unwrap()) as usize;
            at += 6 + length;
        }
        bytes[at..at + 66].fill(0xff);
        bytes.iter_mut().for_each(|byte| *byte ^= key);
        bytes
    }

    #[test]
    fn partial_configurations_need_independent_anchors_and_preserve_failed_checks() {
        for key in KEYS {
            let bytes = partial_fixture(key);
            let rows = scan(&bytes, 0..bytes.len());
            assert_eq!(rows.len(), 2);
            for (_, row) in rows {
                assert!(row.is_partial_match());
                assert!(!row.text("Validation failures").is_empty());
                assert!(row.text("Configuration bytes SHA-256").is_empty());
                assert_eq!(row.text("Candidate bytes SHA-256").len(), 64);
            }
        }
        let mut bytes = partial_fixture(0);
        // Invalid jitter must not survive even though the HTTP strings do.
        let mut at = 0;
        while bytes[at..at + 2] != 5u16.to_be_bytes() {
            at += 6 + u16::from_be_bytes(bytes[at + 4..at + 6].try_into().unwrap()) as usize;
        }
        bytes[at + 6..at + 8].copy_from_slice(&101u16.to_be_bytes());
        assert!(scan(&bytes, 0..bytes.len()).is_empty());
    }

    #[test]
    fn partial_flood_preserves_later_intact_configurations() {
        let mut bytes = Vec::new();
        for _ in 0..MAX_PARTIAL_FINDINGS {
            bytes.extend(partial_fixture(0x2e));
        }
        let strict_at = bytes.len();
        bytes.extend(fixture(0x69));
        let rows = scan(&bytes, 0..bytes.len());
        assert_eq!(
            rows.iter()
                .filter(|(_, row)| row.is_partial_match())
                .count(),
            MAX_PARTIAL_FINDINGS
        );
        assert_eq!(
            rows.iter()
                .filter(|(_, row)| !row.is_partial_match())
                .count(),
            2
        );
        assert_eq!(rows[0].0, strict_at);
    }
    #[test]
    fn stock_blocks_decode_all_supported_keys_and_keep_hostname_pairs() {
        for key in KEYS {
            let bytes = fixture(key);
            let rows = scan(&bytes, 0..bytes.len());
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].1.text("IP"), "192.0.2.5");
            assert_eq!(rows[1].1.text("Hostname"), "example.test");
            assert_eq!(rows[0].1.text("XOR key"), format!("0x{key:02x}"));
        }
    }
    #[test]
    fn malformed_settings_and_marker_strings_never_validate() {
        let mut bytes = fixture(0);
        bytes[4..6].copy_from_slice(&4000u16.to_be_bytes());
        assert!(scan(&bytes, 0..bytes.len()).is_empty());
        assert!(scan(&HEADER, 0..HEADER.len()).is_empty());
        let mut bad = fixture(0);
        bad[16..18].fill(0xff);
        assert!(scan(&bad, 0..bad.len()).is_empty());
        let truncated = &fixture(0)[..60];
        assert!(scan(truncated, 0..truncated.len()).is_empty());
    }
    #[test]
    fn acquisition_scanning_preserves_a_beacon_across_chunk_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("capture.raw");
        let at = 4 * 1024 * 1024 - 12;
        let mut bytes = vec![0xff; at];
        bytes.extend(fixture(0x69));
        std::fs::write(&path, bytes).unwrap();
        let (rows, message, _) =
            super::super::memory::scan(&path, &std::sync::atomic::AtomicBool::new(false), &|_| {})
                .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|r| r.fields["Acquisition offset"] == json!(at))
        );
        assert!(rows.iter().all(|r| !r.fields.contains_key("PID")));
        assert!(message.contains("2 validated Cobalt Strike"));
    }
}
