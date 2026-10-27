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
pub(in crate::analysis) fn discovery_pattern() -> String {
    KEYS.iter()
        .map(|key| {
            HEADER
                .iter()
                .map(|b| format!("\\x{:02x}", b ^ key))
                .collect::<String>()
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
    for (key, needle) in KEYS.iter().zip(needles) {
        for at in memchr::memmem::find_iter(bytes, needle).filter(|at| core.contains(at)) {
            if let Some(found) = parse(&bytes[at..], *key) {
                rows.extend(found.into_iter().map(|row| (at, row)));
            }
            if rows.len() >= super::MAX_FINDINGS {
                return rows;
            }
        }
    }
    rows
}

#[cfg(test)]
pub(in crate::analysis) mod tests {
    use super::*;
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
        let (rows, message) =
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
