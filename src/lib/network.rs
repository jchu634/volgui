//! Network graph projection. Addresses and ports are normalized once, away from rendering.
use crate::{
    results::{Query, ResultStore, StoredRecord},
    volatility::Record,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub address: String,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    Address(String),
    Endpoint(Endpoint),
}
impl Selection {
    pub fn address(&self) -> &str {
        match self {
            Self::Address(ip) => ip,
            Self::Endpoint(e) => &e.address,
        }
    }
    pub fn label(&self) -> String {
        match self {
            Self::Address(ip) => ip.clone(),
            Self::Endpoint(e) => e.label(),
        }
    }
    pub fn matches(&self, entry: &Entry) -> bool {
        match self {
            Self::Address(ip) => entry.matches(ip, None),
            Self::Endpoint(endpoint) => [&entry.local, &entry.remote]
                .into_iter()
                .flatten()
                .any(|e| e == endpoint),
        }
    }
}

impl Endpoint {
    pub fn label(&self) -> String {
        let address = if self.address.contains(':') {
            format!("[{}]", self.address)
        } else {
            self.address.clone()
        };
        match self.port {
            Some(port) => format!("{address}:{port}"),
            None => address,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub source: Arc<StoredRecord>,
    pub local: Option<Endpoint>,
    pub remote: Option<Endpoint>,
    pub protocol: String,
    pub state: String,
    pub pid: String,
    pub owner: String,
    pub created: String,
    pub finding: bool,
    search_text: String,
    priority: u8,
}

impl Entry {
    pub fn from_record(source: StoredRecord) -> Self {
        let r = &source.record;
        let finding = !r.text("Finding").is_empty();
        let search_text = r
            .fields
            .values()
            .map(crate::volatility::display_value)
            .collect::<Vec<_>>()
            .join("\n")
            .to_ascii_lowercase();
        let priority = if !r.text("Password").is_empty() {
            0
        } else if r.text("Finding").contains("Meterpreter") {
            1
        } else if finding {
            2
        } else {
            3
        };
        Self {
            local: endpoint(
                r,
                &["LocalAddr", "LocalAddress", "SrcAddr", "Source"],
                &["LocalPort", "SrcPort", "SourcePort"],
            ),
            remote: if finding {
                endpoint(r, &["IP"], &["Port"])
            } else {
                endpoint(
                    r,
                    &[
                        "ForeignAddr",
                        "RemoteAddr",
                        "RemoteAddress",
                        "DstAddr",
                        "Target",
                    ],
                    &["ForeignPort", "RemotePort", "DstPort", "TargetPort"],
                )
            },
            protocol: field(r, &["Proto", "Protocol"]),
            state: field(r, &["State"]),
            pid: field(r, &["PID", "Pid", "ProcessID"]),
            owner: field(
                r,
                &["Owner", "Process", "ProcessName", "ImageFileName", "COMM"],
            ),
            created: field(r, &["Created", "CreateTime", "StartTime"]),
            source: Arc::new(source),
            finding,
            search_text,
            priority,
        }
    }
    pub fn matches(&self, address: &str, port: Option<u16>) -> bool {
        [&self.local, &self.remote]
            .into_iter()
            .flatten()
            .any(|e| e.address == address && port.is_none_or(|port| e.port == Some(port)))
    }
}

pub fn field(r: &Record, aliases: &[&str]) -> String {
    aliases
        .iter()
        .map(|name| r.text(name))
        .find(|s| !s.is_empty() && s != "N/A" && s != "Unreadable")
        .unwrap_or_default()
}

fn endpoint(r: &Record, addresses: &[&str], ports: &[&str]) -> Option<Endpoint> {
    let value = field(r, addresses);
    let mut port = field(r, ports).parse::<u16>().ok();
    let mut address = value.trim().trim_matches(['[', ']']).to_string();
    if let Ok(socket) = value.parse::<std::net::SocketAddr>() {
        address = socket.ip().to_string();
        port = port.or(Some(socket.port()));
    } else if value.matches(':').count() == 1
        && let Some((host, p)) = value.rsplit_once(':')
        && let Ok(p) = p.parse::<u16>()
    {
        address = host.to_string();
        port = port.or(Some(p));
    }
    if address == "*" {
        return Some(Endpoint { address, port });
    }
    if let Some((ip, zone)) = address.split_once('%') {
        if zone.is_empty() || zone.chars().any(char::is_whitespace) {
            return None;
        }
        address = format!("{}%{zone}", ip.parse::<std::net::Ipv6Addr>().ok()?);
    } else {
        address = address.parse::<IpAddr>().ok()?.to_string();
    }
    Some(Endpoint { address, port })
}

#[derive(Clone, Debug, Default)]
pub struct Graph {
    pub entries: Vec<Entry>,
    pub addresses: BTreeMap<String, BTreeSet<Option<u16>>>,
    pub unplotted: usize,
    pub protocols: BTreeSet<String>,
    pub states: BTreeSet<String>,
    sidebar_order: Vec<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub focus: Option<String>,
    pub text: String,
    pub protocol: Option<String>,
    pub state: Option<String>,
}

#[derive(Default)]
pub struct Overview {
    pub peers: BTreeMap<String, BTreeSet<(Endpoint, Endpoint, String)>>,
    pub references: BTreeMap<String, BTreeSet<Option<u16>>>,
    pub matching: usize,
}

impl Graph {
    pub fn load(
        store: &ResultStore,
        query: &Query,
        epoch: u64,
        token: &AtomicU64,
    ) -> Result<Option<Self>, String> {
        // Graph and endpoint membership use every matching observation, never the visible row cache.
        let ids = store.network_ids(&query.runs)?;
        let mut graph = Self::default();
        for ids in ids.chunks(256) {
            if token.load(Ordering::Relaxed) != epoch {
                return Ok(None);
            }
            for row in store.fetch(ids)? {
                graph.push(Entry::from_record(row));
            }
        }
        graph.sidebar_order = (0..graph.entries.len()).collect();
        graph
            .sidebar_order
            .sort_by_key(|i| graph.entries[*i].priority);
        Ok(Some(graph))
    }
    pub fn push(&mut self, entry: Entry) {
        if !entry.protocol.is_empty() {
            self.protocols.insert(entry.protocol.clone());
        }
        if !entry.state.is_empty() {
            self.states.insert(entry.state.clone());
        }
        if entry.local.is_none() && entry.remote.is_none() {
            self.unplotted += 1;
        }
        for endpoint in [&entry.local, &entry.remote].into_iter().flatten() {
            self.addresses
                .entry(endpoint.address.clone())
                .or_default()
                .insert(endpoint.port);
        }
        self.entries.push(entry);
    }

    pub fn contains_selection(&self, selection: &Selection) -> bool {
        self.addresses
            .get(selection.address())
            .is_some_and(|ports| match selection {
                Selection::Address(_) => true,
                Selection::Endpoint(e) => ports.contains(&e.port),
            })
    }

    pub fn selected_indices(&self, selection: Option<&Selection>) -> Vec<usize> {
        self.sidebar_order
            .iter()
            .copied()
            .filter(|i| selection.is_none_or(|s| s.matches(&self.entries[*i])))
            .collect()
    }

    pub fn overview(&self, filter: &Filter) -> Overview {
        let mut view = Overview::default();
        for entry in &self.entries {
            if filter
                .protocol
                .as_ref()
                .is_some_and(|p| p != &entry.protocol)
                || filter.state.as_ref().is_some_and(|s| s != &entry.state)
                || (if let Some(pid) = filter.text.strip_prefix("pid:") {
                    entry.pid != pid.trim()
                } else {
                    !filter.text.is_empty() && !entry.search_text.contains(&filter.text)
                })
            {
                continue;
            }
            view.matching += 1;
            if entry.finding
                && let Some(remote) = &entry.remote
            {
                view.references
                    .entry(remote.address.clone())
                    .or_default()
                    .insert(remote.port);
                view.peers.entry(remote.address.clone()).or_default();
            }
            let Some(focus) = &filter.focus else {
                continue;
            };
            let pair = match (&entry.local, &entry.remote) {
                (Some(local), Some(remote)) if &local.address == focus => Some((local, remote)),
                (Some(local), Some(remote)) if &remote.address == focus => Some((remote, local)),
                _ => None,
            };
            if let Some((local, remote)) = pair {
                view.peers
                    .entry(remote.address.clone())
                    .or_default()
                    .insert((local.clone(), remote.clone(), entry.protocol.clone()));
            }
        }
        view
    }
}

/// Common assignments are investigation hints, not identification of the actual service.
pub fn service(port: Option<u16>) -> &'static str {
    match port {
        Some(0) => "Unspecified port",
        Some(21) => "FTP control",
        Some(22) => "SSH",
        Some(23) => "Telnet",
        Some(25 | 465 | 587) => "SMTP",
        Some(53) => "DNS",
        Some(67 | 68) => "DHCP",
        Some(80 | 8080) => "HTTP",
        Some(88) => "Kerberos",
        Some(123) => "NTP",
        Some(135) => "RPC endpoint mapper",
        Some(137..=139) => "NetBIOS",
        Some(389 | 636) => "LDAP",
        Some(443 | 8443) => "HTTPS",
        Some(445) => "SMB / Windows file sharing",
        Some(1433) => "Microsoft SQL Server",
        Some(3306) => "MySQL",
        Some(3389) => "Remote Desktop",
        Some(5985 | 5986) => "WinRM",
        None => "Port not recovered",
        _ => "No common service assignment",
    }
}
