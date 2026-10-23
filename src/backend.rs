//! The entire Volatility boundary: OS processes, argument vectors and JSON.
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    thread,
    time::Duration,
};

pub const PREVIEW_LIMIT: u64 = 32 * 1024 * 1024;
pub struct Report {
    pub stdout: tempfile::NamedTempFile,
    pub stderr: tempfile::NamedTempFile,
    pub success: bool,
    pub cancelled: bool,
    pub code: Option<i32>,
    pub preview: Result<Table, String>,
}
pub enum Event {
    Progress(String),
    Finished(Result<Report, String>),
}

pub fn default_engine() -> PathBuf {
    if let Some(path) = std::env::var_os("VOLGUI_VOL") {
        return path.into();
    }
    let name = if cfg!(windows) { "vol.exe" } else { "vol" };
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("vol").join(name);
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from(name)
}

pub fn analysis_args(
    image: &str,
    output: &str,
    analysis: &str,
    options: &str,
    offline: bool,
) -> Result<Vec<String>, String> {
    if !Path::new(image).is_file() {
        return Err("Select an existing memory image.".into());
    }
    if !Path::new(output).is_dir() {
        return Err("Select an existing output directory.".into());
    }
    let extra = shell_words::split(options).map_err(|e| e.to_string())?;
    // All options here belong to the selected analysis, never to a shell.
    let mut args = vec![
        "-q".into(),
        "-r".into(),
        "json".into(),
        "-f".into(),
        image.into(),
        "-o".into(),
        output.into(),
    ];
    if offline {
        args.push("--offline".into());
    }
    args.push(analysis.into());
    args.extend(extra);
    Ok(args)
}

pub fn launch(
    engine: String,
    args: Vec<String>,
    cancel: Arc<AtomicBool>,
    tx: Sender<Event>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let result = (|| -> Result<Report, String> {
            let stdout = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
            let stderr = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
            let mut command = Command::new(engine);
            command
                .args(args)
                .stdin(Stdio::null())
                .stdout(stdout.reopen().map_err(|e| e.to_string())?)
                .stderr(stderr.reopen().map_err(|e| e.to_string())?);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let mut child = command
                .spawn()
                .map_err(|e| format!("Could not start Volatility: {e}"))?;
            let mut cancelled = false;
            let status = loop {
                if cancel.load(Ordering::Relaxed) {
                    cancelled = true;
                    let _ = child.kill();
                    break child.wait().map_err(|e| e.to_string())?;
                }
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => {}
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(e.to_string());
                    }
                }
                if tx
                    .send(Event::Progress(
                        tail(stderr.path(), 12000).unwrap_or_default(),
                    ))
                    .is_err()
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Window closed".into());
                }
                thread::sleep(Duration::from_millis(250));
            };
            let preview = if status.success() && !cancelled {
                parse_table(stdout.path())
            } else {
                Err("No completed JSON result".into())
            };
            Ok(Report {
                stdout,
                stderr,
                success: status.success(),
                cancelled,
                code: status.code(),
                preview,
            })
        })();
        let _ = tx.send(Event::Finished(result));
    })
}

pub fn tail(path: &Path, limit: u64) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(limit)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub truncated: bool,
}
pub fn parse_table(path: &Path) -> Result<Table, String> {
    if path.metadata().map_err(|e| e.to_string())?.len() > PREVIEW_LIMIT {
        return Err("Result exceeds 32 MiB. Export the full JSON to inspect it.".into());
    }
    let value: Value = serde_json::from_reader(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("No JSON table: {e}"))?;
    let nodes = value.as_array().ok_or("Expected a JSON array")?;
    let mut table = Table {
        columns: Vec::new(),
        rows: Vec::new(),
        truncated: false,
    };
    let mut stack: Vec<_> = nodes.iter().rev().map(|v| (v, 0usize)).collect();
    while let Some((node, depth)) = stack.pop() {
        if table.rows.len() == 2000 {
            table.truncated = true;
            break;
        }
        let object = node.as_object().ok_or("Expected a JSON row object")?;
        for key in object.keys().filter(|k| k.as_str() != "__children") {
            if !table.columns.contains(key) {
                table.columns.push(key.clone());
                for row in &mut table.rows {
                    row.push(String::new());
                }
            }
        }
        let mut row: Vec<_> = table
            .columns
            .iter()
            .map(|key| {
                object
                    .get(key)
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        Value::Null => "—".into(),
                        _ => v.to_string(),
                    })
                    .unwrap_or_default()
            })
            .collect();
        if let Some(first) = row.first_mut() {
            *first = format!("{}{first}", "  ".repeat(depth.min(20)));
        }
        table.rows.push(row);
        if let Some(children) = object.get("__children").and_then(Value::as_array) {
            stack.extend(children.iter().rev().map(|v| (v, depth + 1)));
        }
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_options_stay_separate_arguments() {
        let image = tempfile::NamedTempFile::new().unwrap();
        let out = tempfile::tempdir().unwrap();
        let args = analysis_args(
            image.path().to_str().unwrap(),
            out.path().to_str().unwrap(),
            "windows.pslist.PsList",
            "--pid 4 8",
            true,
        )
        .unwrap();
        assert_eq!(
            &args[7..],
            &["--offline", "windows.pslist.PsList", "--pid", "4", "8"]
        );
        assert!(analysis_args("missing", ".", "x", "", false).is_err());
    }
    #[test]
    fn nested_rows_and_missing_columns() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            r#"[{{"PID":4,"__children":[{{"PID":8,"Name":"child"}}]}}]"#
        )
        .unwrap();
        let table = parse_table(file.path()).unwrap();
        assert_eq!(table.rows.len(), 2);
        assert_eq!(table.columns.len(), 2);
        assert_eq!(table.rows[0].len(), 2);
        assert!(table.rows[1].iter().any(|v| v.contains("child")));
    }

    #[test]
    fn preview_limits_do_not_modify_full_output() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let data: Vec<_> = (0..2005).map(|i| serde_json::json!({"PID": i})).collect();
        serde_json::to_writer(&mut file, &data).unwrap();
        file.flush().unwrap();
        let table = parse_table(file.path()).unwrap();
        assert_eq!(table.rows.len(), 2000);
        assert!(table.truncated);
        let full: Vec<Value> = serde_json::from_reader(file.reopen().unwrap()).unwrap();
        assert_eq!(full.len(), 2005);
        file.as_file().set_len(PREVIEW_LIMIT + 1).unwrap();
        assert!(parse_table(file.path()).unwrap_err().contains("32 MiB"));
    }

    fn child_args(name: &str) -> Vec<String> {
        vec![
            "--ignored".into(),
            "--exact".into(),
            format!("backend::tests::{name}"),
            "--nocapture".into(),
        ]
    }
    #[test]
    #[ignore = "subprocess fixture"]
    fn fixture_failure() {
        eprintln!("diagnostic sentinel");
        std::process::exit(7);
    }
    #[test]
    #[ignore = "subprocess fixture"]
    fn fixture_sleep() {
        std::thread::sleep(Duration::from_secs(30));
    }
    #[test]
    fn subprocess_failure_preserves_diagnostics() {
        let (tx, rx) = std::sync::mpsc::channel();
        launch(
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            child_args("fixture_failure"),
            Arc::new(AtomicBool::new(false)),
            tx,
        );
        loop {
            if let Event::Finished(result) = rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                let report = result.unwrap();
                assert!(!report.success);
                assert_eq!(report.code, Some(7));
                assert!(
                    tail(report.stderr.path(), 12000)
                        .unwrap()
                        .contains("diagnostic sentinel")
                );
                break;
            }
        }
    }
    #[test]
    fn cancellation_terminates_child() {
        let (tx, rx) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        launch(
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            child_args("fixture_sleep"),
            cancel.clone(),
            tx,
        );
        std::thread::sleep(Duration::from_millis(100));
        cancel.store(true, Ordering::Relaxed);
        loop {
            if let Event::Finished(result) = rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                assert!(result.unwrap().cancelled);
                break;
            }
        }
    }
}
