// Defines result table columns and cell formatting.
use crate::{
    artifacts::ArtifactGroup,
    volatility::{Record, display_value},
};
use chrono::{DateTime, NaiveDateTime};

/// A displayed column keeps its original field key for sorting and saved widths.
#[derive(Clone, Debug)]
pub struct Column {
    pub key: String,
    pub label: String,
    fields: Vec<String>,
    ports: Vec<String>,
}

impl Column {
    pub fn text(&self, record: &Record) -> String {
        let value = field_text(record, &self.fields);
        if self.key == "Text" {
            return value.split_whitespace().collect::<Vec<_>>().join(" ");
        }
        if self.ports.is_empty() {
            cell_text(&value)
        } else {
            cell_text(&endpoint_text(&value, &field_text(record, &self.ports)))
        }
    }

    /// Each list is a coalesced value; an endpoint adds its port as a tie breaker.
    pub fn sort_fields(&self) -> impl Iterator<Item = &[String]> {
        std::iter::once(self.fields.as_slice())
            .chain((!self.ports.is_empty()).then_some(self.ports.as_slice()))
    }

    pub fn default_width(&self) -> f32 {
        match normalized(&self.label).as_str() {
            "pid" | "ppid" | "tid" | "fd" | "count" | "handles" | "references" | "pointers" => 72.,
            "sessionid" => 96.,
            "threads" => 88.,
            "protocol" => 96.,
            "browser" => 112.,
            "type" => 152.,
            "createtime" | "exittime" | "created" | "modified" | "accesstime" => 240.,
            "process" | "target" | "source" => 220.,
            "path" => 300.,
            "originalpath" | "quarantinepath" | "downloadurl" => 300.,
            "quarantinedat" => 240.,
            "executionevidence" | "originevidence" | "evidencestatus" => 280.,
            "text" => 320.,
            _ => 180.,
        }
    }
}

fn normalized(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn find_fields(available: &[String], aliases: &[&str]) -> Vec<String> {
    aliases
        .iter()
        .flat_map(|alias| {
            available
                .iter()
                .filter(move |name| normalized(name) == normalized(alias))
                .cloned()
        })
        .collect()
}

fn field_text(record: &Record, fields: &[String]) -> String {
    fields
        .iter()
        .filter_map(|field| record.fields.get(field))
        .find(|value| !value.is_null() && value.as_str() != Some(""))
        .map(display_value)
        .unwrap_or_else(|| {
            fields
                .first()
                .map(|field| record.text(field))
                .unwrap_or_default()
        })
}

/// Present common artifact fields in investigation order without changing stored records.
pub fn columns(group: Option<ArtifactGroup>, available: &[String]) -> Vec<Column> {
    let fields: &[(&str, &[&str])] = match group {
        Some(ArtifactGroup::Processes) => &[
            ("Process", &["ImageFileName", "COMM", "Process", "Name"]),
            ("PID", &["PID"]),
            ("SessionID", &["SessionID"]),
            ("Threads", &["Threads"]),
            ("Path", &["Path", "FilePath", "ImagePath"]),
            ("CreateTime", &["CreateTime", "Created", "StartTime"]),
        ],
        Some(ArtifactGroup::Network) => &[
            ("PID", &["PID"]),
            (
                "Target",
                &["ForeignAddr", "RemoteAddr", "DstAddr", "Target"],
            ),
            ("Source", &["LocalAddr", "SrcAddr", "Source"]),
            ("Protocol", &["Proto", "Protocol"]),
            ("State", &["State"]),
            ("Owner", &["Owner", "Process", "ProcessName"]),
            ("Created", &["Created", "CreateTime"]),
        ],
        Some(ArtifactGroup::Files) => &[("Name", &["Name", "FileName", "Path", "FilePath"])],
        Some(ArtifactGroup::Web) => &[
            ("PID", &["PID"]),
            ("Browser", &["Browser"]),
            ("Type", &["Kind"]),
            ("Domain", &["Domain"]),
            ("Search terms", &["Search terms"]),
            ("URL", &["URL"]),
            ("Virtual address", &["Virtual address"]),
        ],
        Some(ArtifactGroup::Downloads) => &[
            ("Finding", &["Finding"]),
            ("Filename", &["Filename"]),
            ("Website URL", &["Website URL"]),
            ("Download URL", &["URL"]),
            ("PID", &["PID"]),
            ("Remote IP", &["Remote IP"]),
            ("Remote port", &["Remote port"]),
            ("Match basis", &["Match basis"]),
        ],
        Some(ArtifactGroup::Quarantine) => &[
            ("Scope", &["Scope"]),
            ("Antivirus", &["Antivirus"]),
            ("Evidence status", &["Evidence status"]),
            ("Threat", &["Threat"]),
            ("Filename", &["Filename"]),
            ("Original path", &["Original path"]),
            ("Quarantined at", &["Quarantined at"]),
            ("Execution evidence", &["Execution evidence"]),
            ("PID", &["PID"]),
            ("Origin evidence", &["Origin evidence"]),
            ("Download URL", &["URL"]),
        ],
        Some(ArtifactGroup::Applications) => &[
            ("PID", &["PID"]),
            ("Application", &["Application"]),
            ("Type", &["Kind"]),
            ("Text", &["Text"]),
            ("Encoding", &["Encoding"]),
            ("Virtual address", &["Virtual address"]),
            ("Occurrences", &["Occurrences"]),
        ],
        Some(ArtifactGroup::Strings) => &[
            ("Offset", &["Offset"]),
            ("Encoding", &["Encoding"]),
            ("Context", &["Context"]),
        ],
        Some(ArtifactGroup::Registry) => &[
            ("Name", &["Name", "FileFullPath", "File output"]),
            ("Type", &["Type"]),
            ("Data", &["Data"]),
            ("Key", &["Key"]),
            ("Last write time", &["Last Write Time", "LastWriteTime"]),
            (
                "Hive offset",
                &["Hive Offset", "Offset", "Offset(V)", "Offset(P)"],
            ),
        ],
        Some(ArtifactGroup::Commands) => &[
            ("PID", &["PID", "ProcessID"]),
            ("Process", &["Process", "ImageFileName", "COMM"]),
            ("Args", &["Args"]),
            ("Data", &["Data"]),
            ("Address", &["Address"]),
            ("ConsoleInfo", &["ConsoleInfo"]),
            ("Property", &["Property"]),
        ],
        Some(ArtifactGroup::Modules) => &[
            ("PID", &["PID", "ProcessID"]),
            ("Name", &["Name"]),
            ("Process", &["Process", "ImageFileName", "COMM"]),
            ("Path", &["Path"]),
            ("Base", &["Base"]),
            ("LoadCount", &["LoadCount"]),
            ("LoadTime", &["LoadTime"]),
            ("Size", &["Size"]),
        ],
        Some(ArtifactGroup::Sessions) => &[
            ("Username", &["Username"]),
            ("PID", &["ProcessID", "PID"]),
            ("Process", &["Process", "ImageFileName", "COMM"]),
            ("Session ID", &["Session ID"]),
            ("Session Type", &["Session Type"]),
            ("Create Time", &["Create Time"]),
        ],
        _ => {
            return available
                .iter()
                .filter(|name| visible_column(name))
                .map(|name| Column {
                    key: name.clone(),
                    label: name.clone(),
                    fields: vec![name.clone()],
                    ports: vec![],
                })
                .collect();
        }
    };
    fields
        .iter()
        .filter_map(|(label, aliases)| {
            let fields = find_fields(available, aliases);
            let key = fields.first()?.clone();
            let ports = if group == Some(ArtifactGroup::Network) {
                endpoint_ports(&key, available)
            } else {
                vec![]
            };
            Some(Column {
                key,
                label: (*label).into(),
                fields,
                ports,
            })
        })
        .collect()
}

fn endpoint_ports(address: &str, available: &[String]) -> Vec<String> {
    let aliases: &[&str] = match normalized(address).as_str() {
        "foreignaddr" | "remoteaddr" | "dstaddr" | "target" => {
            &["ForeignPort", "RemotePort", "DstPort", "TargetPort"]
        }
        "localaddr" | "srcaddr" | "source" => &["LocalPort", "SrcPort", "SourcePort"],
        _ => return vec![],
    };
    find_fields(available, aliases)
}

fn endpoint_text(address: &str, port: &str) -> String {
    if port.is_empty() || matches!(port, "N/A" | "null") {
        return address.into();
    }
    if address.is_empty() || matches!(address, "N/A" | "null") {
        return address.into();
    }
    if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn visible_column(name: &str) -> bool {
    if name == "__source" {
        return false;
    }
    let name: String = name.chars().filter(char::is_ascii_alphanumeric).collect();
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "sourcescan"
            | "audit"
            | "cmd"
            | "fileoutput"
            | "handles"
            | "offset"
            | "offsetv"
            | "offsetp"
            | "wow64"
    )
}

/// Compact table presentation only. The stored value is kept for details and exports.
pub fn cell_text(value: &str) -> String {
    if value.is_empty() || value == "N/A" {
        return "N.A.".into();
    }
    let bytes = value.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' {
        return value.into();
    }
    let timestamp = DateTime::parse_from_rfc3339(value)
        .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%:z"))
        .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f %:z"))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(
                value.strip_suffix(" UTC").unwrap_or(value),
                "%Y-%m-%d %H:%M:%S%.f",
            )
            .map(|time| time.and_utc().fixed_offset())
        });
    match timestamp {
        Ok(time) => time.format("%H:%M:%S (%d-%m-%Y)(%:z)").to_string(),
        Err(_) => value.into(),
    }
}

/// Recover the host for profile artifacts and older saved browser results.
pub fn populate_domain(record: &mut Record) {
    if record
        .fields
        .get("Domain")
        .is_none_or(|value| value.is_null() || value.as_str() == Some(""))
        && let Ok(url) = url::Url::parse(&record.text("URL"))
        && let Some(host) = url.host_str()
    {
        record
            .fields
            .insert("Domain".into(), serde_json::json!(host));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volatility::Table;
    use serde_json::json;

    #[test]
    fn network_columns_combine_endpoints_including_ipv6_and_zero_ports() {
        let table = Table::parse(
            &json!([{
                "PID": 624, "ForeignAddr": "2001:db8::1", "ForeignPort": 443,
                "LocalAddr": "0.0.0.0", "LocalPort": 0, "Proto": "TCPv6",
                "State": "ESTABLISHED", "Owner": "test.exe", "Created": "2026-10-24T07:03:09Z",
                "Offset": 1234,
            }])
            .to_string(),
        )
        .unwrap();
        let columns = columns(Some(ArtifactGroup::Network), &table.columns);
        assert_eq!(
            columns.iter().map(|c| c.label.as_str()).collect::<Vec<_>>(),
            [
                "PID", "Target", "Source", "Protocol", "State", "Owner", "Created"
            ]
        );
        assert_eq!(
            columns
                .iter()
                .map(|c| c.text(&table.rows[0]))
                .collect::<Vec<_>>(),
            [
                "624",
                "[2001:db8::1]:443",
                "0.0.0.0:0",
                "TCPv6",
                "ESTABLISHED",
                "test.exe",
                "07:03:09 (24-10-2026)(+00:00)"
            ]
        );
        assert_eq!(endpoint_text("[::]", "80"), "[::]:80");
        assert_eq!(endpoint_text("*", "*"), "*:*");
        assert_eq!(endpoint_text("198.51.100.1", ""), "198.51.100.1");
        assert_eq!(endpoint_text("N/A", "443"), "N/A");
    }

    #[test]
    fn network_aliases_and_files_keep_their_raw_fields_for_details() {
        let table = Table::parse(
            &json!([{
                "PID": 12, "Dst Addr": "198.51.100.1", "Dst Port": 53,
                "Src Addr": "192.0.2.1", "Src Port": 3000, "Protocol": "UDP",
            }])
            .to_string(),
        )
        .unwrap();
        let network = columns(Some(ArtifactGroup::Network), &table.columns);
        assert_eq!(network[1].text(&table.rows[0]), "198.51.100.1:53");
        assert_eq!(network[2].text(&table.rows[0]), "192.0.2.1:3000");
        let files = columns(
            Some(ArtifactGroup::Files),
            &["FileName".into(), "Offset".into()],
        );
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].label, "Name");
        assert_eq!(files[0].key, "FileName");
        assert_eq!(table.rows[0].text("Dst Port"), "53");
    }

    #[test]
    fn timestamps_keep_their_original_offset_and_drop_fractional_seconds() {
        for value in [
            "2026-10-24T18:03:09.123456+11:00",
            "2026-10-24 18:03:09.123456+11:00",
            "2026-10-24 18:03:09 +11:00",
        ] {
            assert_eq!(cell_text(value), "18:03:09 (24-10-2026)(+11:00)");
        }
        assert_eq!(
            cell_text("2026-10-24T07:03:09Z"),
            "07:03:09 (24-10-2026)(+00:00)"
        );
        assert_eq!(
            cell_text("2026-10-24 07:03:09.000000 UTC"),
            "07:03:09 (24-10-2026)(+00:00)"
        );
        assert_eq!(
            cell_text("2026-10-24T07:03:09-03:30"),
            "07:03:09 (24-10-2026)(-03:30)"
        );
        for value in ["Disabled", "624", "csrss.exe", "2026-10-24", "invalid time"] {
            assert_eq!(cell_text(value), value);
        }
    }
}
