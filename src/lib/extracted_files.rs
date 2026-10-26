// Finds and opens extracted analysis files.
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    case::Case,
    results::StoredRecord,
    volatility::{Installation, Record},
};

pub const DUMP_FILES: &str = "windows.dumpfiles.DumpFiles";

const BLOCKED_SUFFIX: &str = ".volgui-blocked";

fn blocked_marker(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(BLOCKED_SUFFIX);
    PathBuf::from(name)
}

/// Keep a durable record even if antivirus removes the recovered bytes.
pub fn block_artifact(path: &Path, reason: &str) -> Result<(), String> {
    if crate::object_store::block(path, reason)? {
        return Ok(());
    }
    if path.try_exists().is_ok_and(|exists| exists) {
        return Ok(());
    }
    fs::write(blocked_marker(path), reason).map_err(|e| e.to_string())
}

pub fn ensure_openable(path: &Path) -> Result<(), String> {
    crate::object_store::ensure_openable(path)?;
    if blocked_marker(path)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err("Potential malware / unavailable artifact. Opening is blocked.".into());
    }
    Ok(())
}

pub fn open_artifact(path: &Path) -> Result<crate::object_store::ArtifactReader, String> {
    ensure_openable(path)?;
    crate::object_store::open(path).map_err(|error| {
        let reason = format!("Potential malware / unavailable artifact: {error}");
        let _ = block_artifact(path, &reason);
        reason
    })
}

pub const HEX_PAGE_SIZE: u64 = 256;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum ContentEncoding {
    #[default]
    Hex,
    Utf8,
    Utf16Le,
    Utf16Be,
    Sqlite,
}
impl ContentEncoding {
    pub const ALL: [Self; 5] = [
        Self::Hex,
        Self::Utf8,
        Self::Utf16Le,
        Self::Utf16Be,
        Self::Sqlite,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Utf8 => "UTF-8 text",
            Self::Utf16Le => "UTF-16LE text",
            Self::Utf16Be => "UTF-16BE text",
            Self::Sqlite => "SQLite tables",
        }
    }
}

#[derive(Debug)]
pub struct HexPage {
    pub path: PathBuf,
    pub offset: u64,
    pub total: u64,
    pub bytes: Vec<u8>,
}

impl HexPage {
    pub fn decoded(&self, encoding: ContentEncoding) -> String {
        let text = match encoding {
            ContentEncoding::Hex | ContentEncoding::Sqlite => return self.text(),
            ContentEncoding::Utf8 => String::from_utf8_lossy(&self.bytes).into_owned(),
            ContentEncoding::Utf16Le | ContentEncoding::Utf16Be => {
                let units: Vec<_> = self
                    .bytes
                    .chunks_exact(2)
                    .map(|b| {
                        if encoding == ContentEncoding::Utf16Le {
                            u16::from_le_bytes([b[0], b[1]])
                        } else {
                            u16::from_be_bytes([b[0], b[1]])
                        }
                    })
                    .collect();
                String::from_utf16_lossy(&units)
            }
        };
        text.chars()
            .map(|c| {
                if c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
                    '\u{fffd}'
                } else {
                    c
                }
            })
            .collect()
    }
    pub fn read(path: &Path, offset: u64) -> Result<Self, String> {
        let mut file = open_artifact(path)?;
        let total = file.metadata().map_err(|e| e.to_string())?.len();
        let offset = offset.min(total.saturating_sub(1)) / HEX_PAGE_SIZE * HEX_PAGE_SIZE;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take(HEX_PAGE_SIZE)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            path: path.into(),
            offset,
            total,
            bytes,
        })
    }

    pub fn text(&self) -> String {
        use std::fmt::Write;
        let mut text = String::from(
            "Offset            Hex bytes                                         ASCII\n",
        );
        for (i, chunk) in self.bytes.chunks(16).enumerate() {
            let _ = write!(text, "{:016X}  ", self.offset + i as u64 * 16);
            for j in 0..16 {
                if let Some(byte) = chunk.get(j) {
                    let _ = write!(text, "{byte:02X} ");
                } else {
                    text.push_str("   ");
                }
                if j == 7 {
                    text.push(' ');
                }
            }
            text.push_str(" | ");
            for byte in chunk {
                text.push(if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                });
            }
            text.push('\n');
        }
        text
    }
}

/// Reuse only an extraction for this file object and source capture.
pub fn completed_dump<'a>(
    case: &'a Case,
    record: &StoredRecord,
    physical: bool,
) -> Option<&'a crate::case::Run> {
    let source = case
        .document
        .runs
        .iter()
        .find(|run| run.id == record.run_id)?;
    if source.plugin == DUMP_FILES {
        return Some(source);
    }
    let target = FileDumpTarget::from_record(&source.plugin, &record.record)?;
    let arguments = target.arguments(physical);
    case.document.runs.iter().rev().find(|run| {
        run.plugin == DUMP_FILES
            && run.evidence_id == source.evidence_id
            && run.status == crate::case::RunStatus::Completed
            && run.arguments == arguments
    })
}

/// A file object, rather than a path or a process-wide extraction request.
pub struct FileDumpTarget {
    address: u64,
    address_flag: Option<&'static str>,
}

impl FileDumpTarget {
    pub fn from_record(plugin: &str, record: &Record) -> Option<Self> {
        if crate::analysis::files::pseudo_file(&crate::analysis::files::file_path(record)) {
            return None;
        }
        if plugin == crate::analysis::FILES {
            let source = record.text("Source plugin");
            return crate::analysis::files::SOURCES
                .contains(&source.as_str())
                .then(|| Self::from_record(&source, record))
                .flatten();
        }
        let path = crate::analysis::files::file_path(record).to_ascii_lowercase();
        if [
            r"\device\namedpipe",
            r"\device\mailslot",
            r"\device\tcp",
            r"\device\udp",
            r"\device\afd",
        ]
        .iter()
        .any(|device| path == *device || path.starts_with(&format!("{device}\\")))
        {
            return None;
        }
        let fields: &[(&str, Option<&str>)] = match plugin {
            "windows.filescan.FileScan" => &[
                ("Offset(V)", Some("--virtaddr")),
                ("Offset(P)", Some("--physaddr")),
                ("Offset", None),
            ],
            "windows.handles.Handles" if record.text("Type") == "File" => &[
                ("Offset(V)", Some("--virtaddr")),
                ("Offset", Some("--virtaddr")),
            ],
            _ => return None,
        };
        for (column, flag) in fields {
            if let Some(value) = record.fields.get(*column) {
                let address = value.as_u64().or_else(|| {
                    let text = value.as_str()?.trim();
                    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                        Some(hex) => u64::from_str_radix(hex, 16).ok(),
                        None => text.parse().ok(),
                    }
                })?;
                if address == 0 {
                    return None;
                }
                return Some(Self {
                    address,
                    address_flag: *flag,
                });
            }
        }
        None
    }

    /// FileScan's unlabelled Offset uses virtual memory on Windows 10+, physical on older Windows.
    pub fn needs_address_space(&self) -> bool {
        self.address_flag.is_none()
    }

    pub fn arguments(&self, physical_offset: bool) -> Vec<String> {
        vec![
            self.address_flag
                .unwrap_or(if physical_offset {
                    "--physaddr"
                } else {
                    "--virtaddr"
                })
                .into(),
            format!("{:#x}", self.address),
        ]
    }
}

/// Resolve evidence from the source run, even when the UI is browsing another capture.
pub fn queue_file_dump(
    case: &mut Case,
    engine: &Installation,
    record: &StoredRecord,
    physical_offset: bool,
) -> Result<String, String> {
    let source = case
        .document
        .runs
        .iter()
        .find(|run| run.id == record.run_id)
        .ok_or("The source analysis is no longer available")?;
    let target = FileDumpTarget::from_record(&source.plugin, &record.record)
        .ok_or("This result has no supported file object offset")?;
    let evidence = case
        .document
        .evidence
        .iter()
        .find(|e| e.id == source.evidence_id)
        .ok_or("The source evidence is no longer available")?;
    let run = engine.prepare(
        evidence,
        DUMP_FILES,
        target.arguments(physical_offset),
        &case.directory.join("analyses"),
    )?;
    let id = run.id.clone();
    case.queue(run)?;
    Ok(id)
}

/// List plugin-created files without following links outside the analysis directory.
pub fn list(directory: &Path) -> Result<Vec<PathBuf>, String> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(error) => {
                    let _ = block_artifact(&path, &error.to_string());
                    files.push(path);
                    continue;
                }
            };
            if path.to_string_lossy().ends_with(BLOCKED_SUFFIX) {
                let name = path.as_os_str().to_string_lossy();
                files.push(PathBuf::from(name.trim_end_matches(BLOCKED_SUFFIX)));
                continue;
            }
            if kind.is_dir() {
                visit(root, &path, files)?;
            } else if kind.is_file()
                && !(directory == root
                    && matches!(
                        entry.file_name().to_str(),
                        Some("stdout.json" | "stderr.log")
                    ))
            {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = crate::object_store::list(directory)?;
    if !directory.is_dir() && files.is_empty() {
        return Err("Analysis output directory is unavailable".into());
    }
    files.retain(|p| {
        !matches!(
            p.file_name().and_then(|n| n.to_str()),
            Some("stdout.json" | "stderr.log")
        )
    });
    if directory.is_dir() {
        visit(directory, directory, &mut files).map_err(|e| e.to_string())?;
    }
    // Volatility retains output names even when antivirus has removed their bytes.
    if let Ok(table) = crate::volatility::Table::read(&directory.join("stdout.json")) {
        for row in table.rows {
            let name = row.text("File output");
            if (name.starts_with("file.") || name.starts_with("pid."))
                && Path::new(&name).components().count() == 1
                && matches!(
                    Path::new(&name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
                && !matches!(name.as_str(), "stdout.json" | "stderr.log")
            {
                files.push(directory.join(name));
            }
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// A display snapshot. Loading may read archived diagnostics or traverse outputs;
/// callers must load it on a worker and render only the returned values.
pub struct ExtractedFile {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub available: bool,
}

pub fn listing(directory: &Path) -> Result<Vec<ExtractedFile>, String> {
    let files = list(directory)?;
    let mut metadata = crate::object_store::output_metadata(directory)?;
    Ok(files
        .into_iter()
        .map(|path| {
            let info = metadata.remove(&path);
            let available = match &info {
                Some(info) => info.sha256.is_some() && info.blocked_reason.is_none(),
                None => path.is_file() && ensure_openable(&path).is_ok(),
            };
            ExtractedFile {
                path,
                sha256: info.and_then(|info| info.sha256),
                available,
            }
        })
        .collect())
}

pub fn imhex() -> Option<PathBuf> {
    let executable = if cfg!(windows) { "imhex.exe" } else { "imhex" };
    let mut candidates: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(executable))
                .collect()
        })
        .unwrap_or_default();
    if cfg!(windows) {
        for variable in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(variable) {
                candidates.push(PathBuf::from(&base).join("ImHex").join(executable));
                candidates.push(PathBuf::from(base).join("Programs/ImHex").join(executable));
            }
        }
    } else {
        candidates.push("/Applications/ImHex.app/Contents/MacOS/imhex".into());
    }
    candidates.into_iter().find(|path| path.is_file())
}

pub fn open(executable: &Path, file: &Path) -> Result<(), String> {
    let _ = open_artifact(file)?;
    let lease = crate::object_store::materialize(file)?;
    let mut child = Command::new(executable)
        .arg(imhex_path(lease.path()))
        .spawn()
        .map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let _lease = lease;
        let _ = child.wait();
    });
    Ok(())
}

fn imhex_path(file: &Path) -> PathBuf {
    // ImHex's command-line file matching ignores Windows verbatim paths.
    #[cfg(windows)]
    {
        use std::{
            ffi::OsString,
            path::{Component, Prefix},
        };
        let mut components = file.components();
        if let Some(Component::Prefix(prefix)) = components.next() {
            let mut path = match prefix.kind() {
                Prefix::VerbatimDisk(drive) => PathBuf::from(format!("{}:", char::from(drive))),
                Prefix::VerbatimUNC(server, share) => {
                    let mut prefix = OsString::from(r"\\");
                    prefix.push(server);
                    prefix.push(r"\");
                    prefix.push(share);
                    PathBuf::from(prefix)
                }
                _ => return file.to_path_buf(),
            };
            path.push(components.as_path());
            return path;
        }
    }
    file.to_path_buf()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn imhex_receives_standard_absolute_paths_including_network_shares() {
        for (source, expected) in [
            (r"\\?\C:\Case files\résult.dat", r"C:\Case files\résult.dat"),
            (
                r"\\?\UNC\server\share\case\file.dat",
                r"\\server\share\case\file.dat",
            ),
            (r"C:\case\file.dat", r"C:\case\file.dat"),
        ] {
            assert_eq!(imhex_path(Path::new(source)), PathBuf::from(expected));
        }
    }
}
