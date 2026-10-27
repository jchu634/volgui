//! Recover structurally validated payload configurations, without a general string scan.
use crate::volatility::Record;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const CHUNK: usize = 4 * 1024 * 1024;
const OVERLAP: usize = 8192;
const LIMIT: usize = 2_000;
pub(super) const COMPLETE: &str = "Meterpreter TCP configuration";
pub(super) const INCOMPLETE: &str = "Incomplete Meterpreter TCP configuration candidate";

fn session_header(bytes: &[u8], at: usize) -> Option<serde_json::Value> {
    let session = bytes.get(at.checked_sub(48)?..at)?;
    let exit = u32::from_le_bytes(session[8..12].try_into().ok()?);
    let expiry = u32::from_le_bytes(session[12..16].try_into().ok()?);
    if ![0, 0x56a2b5f0, 0x0a2a1de0, 0xea320efe, 0x5de2c5aa].contains(&exit)
        || expiry > 10 * 366 * 86400
        || session[16..32].iter().all(|b| *b == 0)
    {
        return None;
    }
    Some(json!({
        "Exit function":format!("0x{exit:08x}"),
        "Payload UUID":session[16..32].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "Session GUID":session[32..48].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "Session expiry seconds":expiry
    }))
}

// Legacy Meterpreter Windows configuration: 48-byte session, 512 WCHAR URL,
// three DWORD timeouts, then the next transport or a zero terminator.
// https://github.com/rapid7/metasploit-framework/blob/6.3.31/lib/rex/payloads/meterpreter/config.rb
pub(in crate::analysis) fn meterpreter_config(
    bytes: &[u8],
    at: usize,
    address: &str,
) -> Option<serde_json::Value> {
    let mut config = session_header(bytes, at)?;
    let url = bytes.get(at..at + 1024)?;
    let used = address.encode_utf16().count().checked_mul(2)?;
    if used >= 1024 || url.get(used..)?.iter().any(|b| *b != 0) {
        return None;
    }
    let dword =
        |slice: &[u8], i: usize| Some(u32::from_le_bytes(slice.get(i..i + 4)?.try_into().ok()?));
    let timers = bytes.get(at + 1024..at + 1036)?;
    let comms = dword(timers, 0)?;
    let retry = dword(timers, 4)?;
    let wait = dword(timers, 8)?;
    if comms == 0
        || comms > 366 * 86400
        || retry == 0
        || retry > 366 * 86400
        || wait == 0
        || wait > retry
    {
        return None;
    }
    if bytes.get(at + 1036..at + 1038) != Some(&[0, 0][..]) {
        return None;
    }
    config["Communications timeout seconds"] = comms.into();
    config["Retry total seconds"] = retry.into();
    config["Retry wait seconds"] = wait.into();
    Some(config)
}

// Keep damaged or physically fragmented configurations as leads. Require a known
// exit function, plausible session header, terminated URL and some zero padding.
// This never grants the validation or ownership of a complete configuration.
fn incomplete_config(bytes: &[u8], at: usize, address: &str) -> Option<serde_json::Value> {
    let config = session_header(bytes, at)?;
    if config["Exit function"] == "0x00000000" || config["Session expiry seconds"] == 0 {
        return None;
    }
    let used = address.encode_utf16().count().checked_mul(2)?;
    if used + 64 > 1024
        || bytes
            .get(at + used..at + used + 64)?
            .iter()
            .any(|b| *b != 0)
    {
        return None;
    }
    Some(config)
}

pub(super) fn scan(
    path: &Path,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Vec<Record>, String), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let total = file.metadata().map_err(|e| e.to_string())?.len();
    let marker: Vec<_> = "tcp://".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut chunk = vec![0; CHUNK];
    let mut buffer = Vec::with_capacity(CHUNK + OVERLAP * 2);
    let mut base = 0u64;
    let mut scanned = 0u64;
    let mut rows = Vec::new();
    let mut limited = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Network configuration recovery cancelled".into());
        }
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        buffer.extend_from_slice(&chunk[..n]);
        let end = if n == 0 {
            buffer.len()
        } else {
            buffer.len().saturating_sub(OVERLAP)
        };
        let begin = scanned.saturating_sub(base) as usize;
        for (at, mut row) in super::beacon::scan(&buffer, begin..end) {
            row.fields
                .insert("Configuration offset".into(), (base + at as u64).into());
            row.fields
                .insert("Match offset".into(), (base + at as u64).into());
            row.fields
                .insert("Acquisition offset".into(), (base + at as u64).into());
            row.fields.insert(
                "Source type".into(),
                "Validated acquisition configuration".into(),
            );
            row.fields.insert(
                "Ownership evidence".into(),
                "Not recovered; acquisition bytes do not identify an owning process".into(),
            );
            row.fields.insert(
                "Connection evidence".into(),
                "No process-owned connection established by this configuration".into(),
            );
            rows.push(row);
            if rows.len() >= LIMIT {
                limited = true;
                break;
            }
        }
        for at in memchr::memmem::find_iter(&buffer, &marker)
            .filter(|at| *at < end && base + *at as u64 >= scanned)
        {
            if limited {
                break;
            }
            let units: Vec<_> = buffer[at..]
                .chunks_exact(2)
                .take(512)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|unit| *unit != 0)
                .collect();
            let Ok(uri) = String::from_utf16(&units) else {
                continue;
            };
            let complete = meterpreter_config(&buffer, at, &uri);
            let validated = complete.is_some();
            let Some(config) = complete.or_else(|| incomplete_config(&buffer, at, &uri)) else {
                continue;
            };
            let Some(mut row) = super::parse_text(&uri)
                .into_iter()
                .find(|r| r.text("Finding") == "TCP transport endpoint" && r.text("URI") == uri)
            else {
                continue;
            };
            row.fields.insert(
                "Finding".into(),
                if validated { COMPLETE } else { INCOMPLETE }.into(),
            );
            for field in ["Payload UUID", "Session GUID"] {
                row.fields.insert(field.into(), config[field].clone());
            }
            row.fields.insert("Payload configuration".into(), config);
            if validated {
                row.fields.insert(
                    "Configuration bytes SHA-256".into(),
                    format!("{:x}", Sha256::digest(&buffer[at - 48..at + 1038])).into(),
                );
            }
            row.fields.insert(
                "Configuration offset".into(),
                (base + at as u64 - 48).into(),
            );
            row.fields
                .insert("Acquisition offset".into(), (base + at as u64 - 48).into());
            row.fields
                .insert("Match offset".into(), (base + at as u64).into());
            row.fields.insert("Encoding".into(), "UTF-16LE".into());
            row.fields.insert(
                "Source type".into(),
                if validated {
                    "Validated acquisition configuration"
                } else {
                    "Incomplete acquisition configuration"
                }
                .into(),
            );
            row.fields.insert("Validation".into(), if validated {
                "Complete legacy session and TCP transport layout"
            } else {
                "Session header, TCP URL and initial padding only; full URL padding, timeouts or transport terminator are missing or invalid"
            }.into());
            row.fields.insert(
                "Ownership evidence".into(),
                "Not recovered; acquisition bytes do not identify an owning process".into(),
            );
            row.fields.insert(
                "Connection evidence".into(),
                "No process-owned connection established by this configuration".into(),
            );
            row.fields.insert("Interpretation".into(), if validated {
                "Legacy Meterpreter session and TCP transport layout validated, including URL padding, payload UUID, exit function and timeouts. This is a configured endpoint; process ownership and a successful connection require separate evidence."
            } else {
                "Incomplete Meterpreter configuration candidate. A plausible session header precedes an explicit TCP URL, but the full transport structure did not validate. Physical pages may be fragmented or overwritten. This lead does not establish a configured payload, process ownership or a successful connection."
            }.into());
            rows.push(row);
            if rows.len() >= LIMIT {
                limited = true;
                break;
            }
        }
        scanned = base + end as u64;
        progress(format!(
            "Network payload configurations: {} / {} MiB",
            (base + buffer.len() as u64) / 1048576,
            total / 1048576
        ));
        if n == 0 || limited {
            break;
        }
        // Retain the preceding session and the following transport across chunk boundaries.
        let discard = end.saturating_sub(OVERLAP);
        buffer.drain(..discard);
        base += discard as u64;
    }
    let validated = rows
        .iter()
        .filter(|r| r.text("Finding") == COMPLETE)
        .count();
    let beacon = rows
        .iter()
        .filter(|r| r.text("Program") == super::beacon::FAMILY)
        .count();
    let message = format!(
        "{validated} validated Meterpreter TCP configurations; {} incomplete configuration candidates. {beacon} validated Cobalt Strike HTTP(S) endpoint configurations. {}Acquisition configurations have no established process owner. Only structured payload configurations and explicitly labelled incomplete headers are recovered; arbitrary strings and credentials are not recovered.",
        rows.len() - validated - beacon,
        if limited {
            "Stopped at the 2,000 configuration limit. "
        } else {
            ""
        }
    );
    Ok((rows, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn meterpreter_configuration_needs_the_structure_not_just_a_tcp_url() {
        let address = "tcp://192.0.2.5:5059";
        let mut bytes = vec![0; 48 + 1038];
        bytes[8..12].copy_from_slice(&0x56a2b5f0u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&604800u32.to_le_bytes());
        bytes[16..32].copy_from_slice(&[0x11; 16]);
        let url = address
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        bytes[48..48 + url.len()].copy_from_slice(&url);
        for (i, v) in [300u32, 3600, 10].into_iter().enumerate() {
            bytes[48 + 1024 + i * 4..48 + 1028 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        assert!(meterpreter_config(&bytes, 48, address).is_some());
        bytes[48 + 100] = 1;
        assert!(meterpreter_config(&bytes, 48, address).is_none());
        bytes[48 + 100] = 0;
        bytes[8..12].fill(0xff);
        assert!(meterpreter_config(&bytes, 48, address).is_none());
        assert!(meterpreter_config(&bytes[..48 + 100], 48, address).is_none());
    }

    #[test]
    fn incomplete_headers_require_session_identity_and_padding() {
        let address = "tcp://192.0.2.5:5059";
        let mut bytes = vec![0; 512];
        bytes[8..12].copy_from_slice(&0x56a2b5f0u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&604800u32.to_le_bytes());
        bytes[16..32].fill(0x11);
        let url: Vec<_> = address.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes[48..48 + url.len()].copy_from_slice(&url);
        assert!(incomplete_config(&bytes, 48, address).is_some());
        assert!(meterpreter_config(&bytes, 48, address).is_none());
        bytes[48 + url.len()] = 1;
        assert!(incomplete_config(&bytes, 48, address).is_none());
        bytes[48 + url.len()] = 0;
        bytes[8..12].fill(0);
        assert!(incomplete_config(&bytes, 48, address).is_none());
        bytes[8..12].copy_from_slice(&0x56a2b5f0u32.to_le_bytes());
        bytes[16..32].fill(0);
        assert!(incomplete_config(&bytes, 48, address).is_none());
    }
}
