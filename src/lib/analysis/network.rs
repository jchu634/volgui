//! Correlate explicit network commands and share references in collected engine records.
//! Text findings retain their provenance and never masquerade as observed sockets.
mod memory;

use super::{record, table};
use crate::{
    case::{CaseSnapshot, Run, RunStatus},
    results::{Query, ResultStore},
    volatility::{Record, Table},
};
use regex::Regex;
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

pub const MAX_FINDINGS: usize = 20_000;
pub const PARSER_VERSION: &str = "network-v3-configurations";
pub const SOURCES: &[&str] = &[
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
    "windows.pslist.PsList",
    "windows.cmdline.CmdLine",
    "windows.cmdscan.CmdScan",
    "windows.consoles.Consoles",
    "windows.handles.Handles",
];

/// Socket inventories alone cannot contain recovered payload configuration.
/// Reuse a completed current parser, or let the existing queued parser finish.
pub fn needs_recovery(document: &CaseSnapshot, evidence_id: &str) -> bool {
    !document.runs.iter().any(|run| {
        run.evidence_id == evidence_id
            && run.plugin == super::NETWORK
            && (matches!(run.status, RunStatus::Queued | RunStatus::Running)
                || (run.status == RunStatus::Completed && run.message.contains(PARSER_VERSION)))
    })
}

fn unc_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\\\\(?P<host>\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+)\\(?P<share>[^\s\x00\x22\x27<>|;&]+)",
        )
        .unwrap()
    })
}

/// Parse only explicit syntax. Port numbers alone are never classified as reverse shells.
pub fn parse_text(text: &str) -> Vec<Record> {
    let lower = text.to_ascii_lowercase();
    let mut rows = Vec::new();
    static URI: OnceLock<Regex> = OnceLock::new();
    let uri = URI.get_or_init(|| {
        Regex::new(r"(?i)\btcp://(?P<host>\[[0-9a-f:]+\]|[0-9.]+):(?P<port>[0-9]{1,5})\b").unwrap()
    });
    for capture in uri.captures_iter(text) {
        if let (Ok(ip), Ok(port)) = (
            capture["host"].trim_matches(['[', ']']).parse::<IpAddr>(),
            capture["port"].parse::<u16>(),
        ) {
            rows.push(record(serde_json::json!({"Finding":"TCP transport endpoint", "IP":ip.to_string(), "Port":port, "URI":capture.get(0).unwrap().as_str(), "Context":text,"Interpretation":"Explicit TCP transport URL in recovered text; identify the owning payload before classifying it as a reverse shell."})));
        }
    }
    for capture in unc_pattern().captures_iter(text) {
        let host = capture["host"].trim_matches(['[', ']']);
        let Ok(ip) = host.parse::<IpAddr>() else {
            continue;
        };
        let mut row = record(
            serde_json::json!({"Finding":"SMB share reference", "IP":ip.to_string(), "Port":445, "Share":capture.get(0).unwrap().as_str(), "Context":text, "Interpretation":"Recovered text references a share; access is not established by this string."}),
        );
        if let Some(command) = drive_command(text, capture.get(0).unwrap().start()) {
            let tokens = command_tokens(command);
            if let Some(share_index) = tokens
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case(capture.get(0).unwrap().as_str()))
            {
                row.fields
                    .insert("Finding".into(), "Network drive command".into());
                let mut positional = Vec::new();
                let mut skip_value = false;
                for (i, arg) in tokens.iter().enumerate().skip(2) {
                    if skip_value {
                        skip_value = false;
                        continue;
                    }
                    if let Some((key, value)) = arg.split_once(':')
                        && (key.eq_ignore_ascii_case("/user") || key.eq_ignore_ascii_case("/u"))
                    {
                        let username = if value.is_empty() {
                            skip_value = true;
                            tokens.get(i + 1).map(String::as_str).unwrap_or("")
                        } else {
                            value
                        };
                        if !username.is_empty() {
                            row.fields.insert("Username".into(), username.into());
                        }
                    } else if i > share_index && !arg.starts_with('/') {
                        positional.push(arg);
                    }
                }
                if let [password] = positional.as_slice()
                    && password.as_str() != "*"
                    && !password.ends_with(':')
                {
                    row.fields
                        .insert("Password".into(), (*password).clone().into());
                }
            }
        }
        rows.push(row);
    }
    static TCP: OnceLock<Regex> = OnceLock::new();
    let tcp = TCP.get_or_init(|| Regex::new(r#"(?i)(?:net\.sockets\.)?tcpclient\s*\(\s*['\"](?P<ip>[0-9a-f:.]+)['\"]\s*,\s*(?P<port>\d{1,5})\s*\)"#).unwrap());
    for capture in tcp.captures_iter(text) {
        if let (Ok(ip), Ok(port)) = (
            capture["ip"].parse::<IpAddr>(),
            capture["port"].parse::<u16>(),
        ) {
            let shell = lower.contains("iex")
                || lower.contains("invoke-expression")
                || lower.contains("cmd.exe");
            rows.push(record(serde_json::json!({"Finding":if shell {"Reverse shell command candidate"} else {"TCP client command"},"IP":ip.to_string(),"Port":port,"Context":text,"Interpretation":"Explicit connection target in recovered text; execution requires corroboration."})));
        }
    }
    let tokens = command_tokens(text);
    if let Some(index) = tokens.iter().position(|s| {
        matches!(
            s.rsplit(['/', '\\'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str(),
            "nc" | "nc.exe" | "ncat" | "ncat.exe" | "netcat" | "netcat.exe"
        )
    }) {
        let args = &tokens[index + 1..];
        if args.iter().any(|s| s == "-e" || s == "--exec" || s == "-c")
            && !args.iter().any(|s| s == "-l" || s == "--listen")
        {
            for pair in args.windows(2) {
                if let (Ok(ip), Ok(port)) = (pair[0].parse::<IpAddr>(), pair[1].parse::<u16>()) {
                    rows.push(record(serde_json::json!({"Finding":"Reverse shell command candidate","IP":ip.to_string(),"Port":port,"Context":text,"Interpretation":"Netcat command specifies a remote target and command execution; execution requires corroboration."})));
                }
            }
        }
    }
    for row in &mut rows {
        row.fields
            .insert("Parser version".into(), PARSER_VERSION.into());
    }
    rows
}

/// Scope a share to its own command, respecting quoted arguments and shell separators.
fn drive_command(text: &str, share_at: usize) -> Option<&str> {
    static COMMAND: OnceLock<Regex> = OnceLock::new();
    let pattern = COMMAND.get_or_init(|| Regex::new(r"(?i)\bnet(?:\.exe)?\s+use\s+").unwrap());
    let command = pattern.find_iter(&text[..share_at]).last()?;
    let start = command.start();
    let outer_quote = start
        .checked_sub(1)
        .and_then(|i| text.as_bytes().get(i))
        .copied()
        .filter(|b| matches!(b, b'"' | b'\''));
    let mut quote = None;
    let mut end = text.len();
    for (relative, ch) in text[start..].char_indices() {
        if outer_quote.is_some_and(|q| char::from(q) == ch) {
            end = start + relative;
            break;
        }
        if matches!(ch, '"' | '\'') && quote.is_none_or(|q| q == ch) {
            quote = if quote.is_some() { None } else { Some(ch) };
        } else if quote.is_none() && matches!(ch, '&' | '|' | ';' | '\n' | '\r') {
            end = start + relative;
            break;
        }
    }
    (share_at < end).then_some(&text[start..end])
}

fn command_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in text.chars() {
        if matches!(ch, '\'' | '"') && quote.is_none_or(|q| q == ch) {
            quote = if quote.is_some() { None } else { Some(ch) };
        } else if ch.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

pub fn analyze(
    directory: &Path,
    document: &CaseSnapshot,
    run: &Run,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<(Table, String), String> {
    let evidence = document
        .evidence
        .iter()
        .find(|e| e.id == run.evidence_id)
        .ok_or("Missing evidence")?;
    let (mut rows, configuration_coverage) = memory::scan(&evidence.path, cancel, progress)?;
    let mut seen = BTreeSet::new();
    // Pin interpretation to inventories preceding this parser job, never later results.
    let preceding = document.runs.iter().take_while(|r| r.id != run.id);
    let preceding: Vec<_> = preceding.collect();
    let missing: Vec<_> = SOURCES
        .iter()
        .filter(|plugin| {
            !preceding.iter().any(|r| {
                r.evidence_id == run.evidence_id
                    && r.plugin == **plugin
                    && r.status == RunStatus::Completed
            })
        })
        .copied()
        .collect();
    let coverage = if missing.is_empty() {
        "All supported source inventories completed.".to_string()
    } else {
        format!(
            "Source inventories unavailable or not completed: {}. Command and credential recovery uses collected records only.",
            missing.join(", ")
        )
    };
    let coverage = format!("{coverage} {configuration_coverage}");
    let source_runs: Vec<_> = preceding
        .into_iter()
        .filter(|r| {
            r.evidence_id == run.evidence_id
                && r.status == RunStatus::Completed
                && SOURCES.contains(&r.plugin.as_str())
        })
        .map(|r| r.id.clone())
        .collect();
    let store = ResultStore::at(directory);
    let index = store.query(&Query {
        runs: source_runs,
        ..Default::default()
    })?;
    for (batch, ids) in index.ids.chunks(256).enumerate() {
        progress(format!(
            "Network source records: {} / {}",
            (batch * 256).min(index.ids.len()),
            index.ids.len()
        ));
        if cancel.load(Ordering::Relaxed) {
            return Err("Network analysis cancelled".into());
        }
        for source in store.fetch(ids)? {
            for (field, value) in &source.record.fields {
                let Some(text) = value.as_str() else { continue };
                for mut row in parse_text(text) {
                    let key = (
                        source.id,
                        field.clone(),
                        row.text("Finding"),
                        row.text("IP"),
                        row.text("Port"),
                        row.text("URI"),
                        row.text("Share"),
                        row.text("Username"),
                        row.text("Password"),
                    );
                    if !seen.insert(key) {
                        continue;
                    }
                    row.fields
                        .insert("Source run".into(), source.run_id.clone().into());
                    row.fields.insert("Source row".into(), source.row.into());
                    row.fields
                        .insert("Source field".into(), field.clone().into());
                    row.fields
                        .insert("Source type".into(), "Engine record text".into());
                    for name in ["PID", "Process", "Owner", "Created"] {
                        if let Some(value) = source.record.fields.get(name) {
                            row.fields.insert(name.into(), value.clone());
                        }
                    }
                    rows.push(row);
                    if rows.len() >= MAX_FINDINGS {
                        for row in &mut rows {
                            row.fields
                                .insert("Evidence SHA-256".into(), evidence.sha256.clone().into());
                        }
                        let (table, message) = finish(rows, true);
                        return Ok((table, format!("{message} {coverage}")));
                    }
                }
            }
        }
    }
    let limited = rows.len() >= MAX_FINDINGS;
    for row in &mut rows {
        row.fields
            .insert("Evidence SHA-256".into(), evidence.sha256.clone().into());
    }
    let (table, message) = finish(rows, limited);
    Ok((table, format!("{message} {coverage}")))
}

fn finish(rows: Vec<Record>, limited: bool) -> (Table, String) {
    let message = format!(
        "{} network findings. {}Parser: {PARSER_VERSION}. Correlated collected engine records and validated payload configurations. Credentials are extracted only from explicit network drive commands. Recovered command text does not prove execution. Socket records remain separate in Network.",
        rows.len(),
        if limited {
            "Stopped at the 20,000 finding limit. "
        } else {
            ""
        }
    );
    (table(rows), message)
}
