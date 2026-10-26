// Defines artifact groups and operating systems.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    #[default]
    Unknown,
    Windows,
    Linux,
    Macos,
}

impl OperatingSystem {
    pub const TARGETS: [Self; 3] = [Self::Windows, Self::Linux, Self::Macos];
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::Macos => "macOS",
        }
    }
    pub fn for_plugin(id: &str) -> Self {
        match id.split('.').next() {
            Some("windows") => Self::Windows,
            Some("linux") => Self::Linux,
            Some("mac") => Self::Macos,
            _ => Self::Unknown,
        }
    }
    pub fn accepts(self, id: &str) -> bool {
        let os = Self::for_plugin(id);
        os == Self::Unknown || os == self || self == Self::Unknown
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactGroup {
    Processes,
    Network,
    Files,
    Web,
    Downloads,
    Quarantine,
    Applications,
    Strings,
    Registry,
    Memory,
    System,
    Commands,
    Modules,
    Sessions,
    Other,
}
impl ArtifactGroup {
    pub const BROWSER: [Self; 9] = [
        Self::Processes,
        Self::Network,
        Self::Files,
        Self::Downloads,
        Self::Quarantine,
        Self::Web,
        Self::Applications,
        Self::Registry,
        Self::Strings,
    ];
    pub const SHORTCUTS: [Self; 6] = [
        Self::Memory,
        Self::System,
        Self::Commands,
        Self::Modules,
        Self::Sessions,
        Self::Other,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Processes => "Processes",
            Self::Network => "Network",
            Self::Files => "Files and documents",
            Self::Web => "Browser activity",
            Self::Downloads => "Download investigation",
            Self::Quarantine => "Quarantined threats",
            Self::Applications => "Process Memory",
            Self::Strings => "Global string search",
            Self::Registry => "Registry",
            Self::Memory => "Memory scan results",
            Self::System => "System information",
            Self::Commands => "Command history",
            Self::Modules => "Loaded modules",
            Self::Sessions => "User sessions",
            Self::Other => "Other artifacts",
        }
    }
    pub fn for_plugin(plugin: &str) -> Self {
        // An ADS row describes a stream and its resident bytes, not a recoverable FILE_OBJECT.
        if plugin == "windows.mftscan.ADS" {
            return Self::Other;
        }
        if plugin == crate::analysis::DOWNLOADS {
            return Self::Downloads;
        }
        if plugin == crate::analysis::QUARANTINE {
            return Self::Quarantine;
        }
        if plugin == crate::analysis::NETWORK {
            return Self::Network;
        }
        if plugin == crate::analysis::APPLICATION {
            return Self::Applications;
        }
        if plugin == crate::analysis::BROWSER {
            return Self::Web;
        }
        if plugin == crate::analysis::STRINGS {
            return Self::Strings;
        }
        let parts: Vec<_> = plugin.split('.').collect();
        let name = parts
            .get(parts.len().saturating_sub(2))
            .copied()
            .unwrap_or("")
            .to_lowercase();
        if parts.contains(&"registry")
            || matches!(
                name.as_str(),
                "hivelist" | "hivescan" | "printkey" | "userassist" | "amcache" | "shimcachemem"
            )
        {
            return Self::Registry;
        }
        if parts.contains(&"malware")
            || matches!(
                name.as_str(),
                "malfind"
                    | "psxview"
                    | "hollowprocesses"
                    | "yarascan"
                    | "vadyarascan"
                    | "suspicious_threads"
                    | "check_creds"
                    | "hidden_modules"
            )
        {
            return Self::Memory;
        }
        match name.as_str() {
            "pslist" | "pstree" | "psscan" | "psaux" => Self::Processes,
            "netscan" | "netstat" | "sockstat" | "sockscan" | "ip" | "ifconfig" | "netfilter" => {
                Self::Network
            }
            "filescan" | "dumpfiles" | "handles" | "lsof" | "mftscan" | "files" | "list_files"
            | "mountinfo" => Self::Files,
            "info" | "banners" | "boottime" | "crashinfo" | "kmsg" | "dmesg" => Self::System,
            "cmdline" | "cmdscan" | "consoles" | "bash" | "envars" => Self::Commands,
            "dlllist" | "ldrmodules" | "modules" | "modscan" | "lsmod" | "library_list"
            | "unloadedmodules" => Self::Modules,
            "sessions" | "getsids" | "getservicesids" => Self::Sessions,
            _ => Self::Other,
        }
    }
}
