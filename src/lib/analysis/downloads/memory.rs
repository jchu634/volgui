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
    if bytes.get(NAME + name.len()) != Some(&0) {
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
    let mut failures = Vec::new();
    if bytes[0] != 3 {
        failures.push(format!(
            "Process header is 0x{:02x}; expected 0x03",
            bytes[0]
        ));
    }
    if dtb == 0 || dtb & 0xfff != 0 {
        failures.push(format!(
            "Directory table base 0x{dtb:x} is zero or not page aligned"
        ));
    }
    if link >> 48 != 0xffff || link & 7 != 0 || integer(bytes, 16)? != link {
        failures.push("Dispatcher links fail the supported process layout checks".into());
    }
    let partial = !failures.is_empty();
    // A damaged leading region is admissible only when the surviving process
    // identity has a valid time, terminated name, and two aligned kernel links.
    if partial
        && [0x448, 0x450].into_iter().any(|at| {
            integer(bytes, at).is_none_or(|pointer| pointer >> 48 != 0xffff || pointer & 7 != 0)
        })
    {
        return None;
    }
    let mut row = record(
        json!({"PID":pid,"PPID":parent,"Process":name,"CreateTime":birth.to_rfc3339(),
        "ExitTime":exit,"Profile":PROFILE,"Directory table base":format!("0x{dtb:x}")}),
    );
    if partial {
        row.fields.insert("Partial match".into(), true.into());
        row.fields
            .insert("Partial match kind".into(), "Residual process".into());
        row.fields
            .insert("Validation failures".into(), json!(failures));
        row.fields.insert(
            "Process header".into(),
            format!("0x{:02x}", bytes[0]).into(),
        );
    }
    Some(row)
}

pub(super) fn scan(
    path: &Path,
    names: &BTreeSet<String>,
    anchors: &[(u64, String, String)],
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Vec<Record>, String, bool), String> {
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
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let total = file.metadata().map_err(|e| e.to_string())?.len();
    let mut chunk = vec![0; CHUNK];
    let mut buffer = Vec::with_capacity(CHUNK + OVERLAP);
    let mut base = 0u64;
    let mut scanned = 0u64;
    let mut matches = BTreeMap::new();
    let mut partial_matches = BTreeMap::new();
    let mut reference = BTreeSet::new();
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
                        if !row.is_partial_match()
                            && anchors.iter().any(|(id, expected, time)| {
                                *id == pid
                                    && expected == name
                                    && (*time - birth).num_milliseconds().abs() < 1000
                            })
                        {
                            reference.insert(pid);
                        }
                        let findings = if row.is_partial_match() {
                            &mut partial_matches
                        } else {
                            &mut matches
                        };
                        let key = (pid, name.clone(), row.text("CreateTime"));
                        if names.contains(name)
                            && (findings.len() < LIMIT || findings.contains_key(&key))
                        {
                            row.fields.insert(
                                "Acquisition offset".into(),
                                (base + (at - NAME) as u64).into(),
                            );
                            row.fields
                                .insert("Match offset".into(), (base + at as u64).into());
                            findings.insert(key, row);
                        } else if names.contains(name) {
                            limited = true;
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
    // Partial candidates have their own bound and never displace intact copies.
    partial_matches.retain(|key, _| !matches.contains_key(key));
    matches.extend(partial_matches);
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
    let partial_count = processes
        .iter()
        .filter(|row: &&Record| row.is_partial_match())
        .count();
    let message = format!(
        "Scanned {total} acquisition bytes. Residual process profile {} against {} inventory PIDs. {partial_count} partial process candidates retained; hidden unless Show partial matches is enabled. Carved process copies do not establish acquisition-time activity.{}",
        if enabled { "validated" } else { "not enabled" },
        reference.len(),
        if limited {
            " Residual finding limit reached."
        } else {
            ""
        }
    );
    Ok((processes, message, limited))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
        let (found, message, _) =
            scan(&path, &names, &anchors, &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(found.len(), 1, "{message}");
        assert_eq!(found[0].fields["Acquisition offset"], base);
        assert_eq!(found[0].fields["PID"], 900);
        let (found, message, _) = scan(
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
    fn damaged_leading_fields_need_a_surviving_process_identity() {
        let birth = 133390291766718843;
        let latest = filetime(birth).unwrap();
        let mut bytes = vec![0; 0x1000];
        process(&mut bytes, 0, "wbadmin.exe", 12228, birth);
        bytes[0] = 0x48;
        bytes[0x28..0x30].copy_from_slice(&0xe4800000800u64.to_le_bytes());
        for at in [0x448, 0x450] {
            bytes[at..at + 8].copy_from_slice(&0xffff9b06f7957508u64.to_le_bytes());
        }
        let row = candidate(&bytes, NAME, "wbadmin.exe", latest).unwrap();
        assert!(row.is_partial_match());
        assert_eq!(row.fields["PID"], 12228);
        assert_eq!(
            row.fields["Validation failures"].as_array().unwrap().len(),
            2
        );
        let good = bytes.clone();
        for range in [CREATED..CREATED + 8, 0x448..0x450] {
            bytes = good.clone();
            bytes[range].fill(0);
            assert!(candidate(&bytes, NAME, "wbadmin.exe", latest).is_none());
        }
        bytes = good;
        bytes[NAME + 11] = b'x';
        assert!(candidate(&bytes, NAME, "wbadmin.exe", latest).is_none());
    }

    #[test]
    fn partial_copies_cannot_corroborate_a_profile_or_displace_an_intact_copy() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("partial.raw");
        let birth = 133390291766718843;
        let latest = filetime(birth).unwrap().to_rfc3339();
        let mut bytes = vec![0; 0x10000];
        let mut anchors = Vec::new();
        for i in 0..5 {
            let base = 4096 * i;
            let name = format!("anchor{i}.exe");
            let pid = 100 + i as u64 * 4;
            process(&mut bytes, base, &name, pid, birth);
            bytes[base] = 0x48;
            for at in [0x448, 0x450] {
                bytes[base + at..base + at + 8]
                    .copy_from_slice(&0xffff800000001008u64.to_le_bytes());
            }
            anchors.push((pid, name, latest.clone()));
        }
        process(&mut bytes, 0x6000, "payload.exe", 900, birth);
        fs::write(&path, &bytes).unwrap();
        let names = ["payload.exe".into()].into();
        let (found, message, _) =
            scan(&path, &names, &anchors, &AtomicBool::new(false), &|_| {}).unwrap();
        assert!(found.is_empty(), "{message}");
        assert!(message.contains("not enabled against 0"));

        for i in 0..5 {
            bytes[4096 * i] = 3;
        }
        process(&mut bytes, 0x8000, "payload.exe", 900, birth);
        bytes[0x8000] = 0x48;
        for at in [0x448, 0x450] {
            bytes[0x8000 + at..0x8000 + at + 8]
                .copy_from_slice(&0xffff800000001008u64.to_le_bytes());
        }
        fs::write(&path, &bytes).unwrap();
        let (found, message, _) =
            scan(&path, &names, &anchors, &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(found.len(), 1, "{message}");
        assert!(!found[0].is_partial_match());
        assert_eq!(found[0].fields["Acquisition offset"], 0x6000);
    }
}
