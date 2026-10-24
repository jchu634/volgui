use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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
        .arg(file)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}
