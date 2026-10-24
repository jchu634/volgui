use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    case::Case,
    results::StoredRecord,
    volatility::{Installation, Record},
};

pub const DUMP_FILES: &str = "windows.dumpfiles.DumpFiles";

/// A file object, rather than a path or a process-wide extraction request.
pub struct FileDumpTarget {
    address: u64,
    address_flag: Option<&'static str>,
}

impl FileDumpTarget {
    pub fn from_record(plugin: &str, record: &Record) -> Option<Self> {
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
            let kind = entry.file_type()?;
            let path = entry.path();
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
    let mut files = Vec::new();
    visit(directory, directory, &mut files).map_err(|e| e.to_string())?;
    files.sort();
    Ok(files)
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
    let file = file.canonicalize().map_err(|e| e.to_string())?;
    Command::new(executable)
        .arg(imhex_path(&file))
        .spawn()
        .map_err(|e| e.to_string())?;
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
