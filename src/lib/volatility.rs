// Validates and runs the Volatility command line engine.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use uuid::Uuid;

use crate::{
    case::{Evidence, Result, Run, RunStatus, now},
    settings::Settings,
};

#[derive(Clone, Debug)]
pub struct Plugin {
    pub id: String,
    pub description: String,
}

#[derive(Clone)]
pub struct Installation {
    pub settings: Settings,
    pub version: String,
    pub plugins: Vec<Plugin>,
}

impl Installation {
    pub fn discover(mut settings: Settings, cancel: &AtomicBool) -> Result<Self> {
        if settings.executable.is_dir() {
            settings.executable =
                settings
                    .executable
                    .join(if cfg!(windows) { "vol.exe" } else { "vol" });
        }
        settings.executable = settings
            .executable
            .canonicalize()
            .map_err(|e| format!("Choose the installed Volatility executable: {e}"))?;
        if !settings.executable.is_file() {
            return Err("Volatility path must be an executable file".into());
        }
        if !settings.symbols.as_os_str().is_empty() {
            settings.symbols = settings
                .symbols
                .canonicalize()
                .map_err(|e| format!("Symbols directory is unavailable: {e}"))?;
            if !settings.symbols.is_dir() {
                return Err("Symbols path must be a directory".into());
            }
        }
        let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
        let args = vec!["--help".into()];
        let captured = capture(
            &settings.executable,
            &args,
            scratch.path(),
            cancel,
            Some(Duration::from_secs(60)),
        )?;
        if captured.cancelled {
            return Err("Engine validation cancelled".into());
        }
        if captured.exit_code != Some(0) {
            return Err(format!(
                "Volatility validation failed: {}",
                read_tail(&scratch.path().join("stderr.log"))
            ));
        }
        let help = read_text(&scratch.path().join("stdout.json"), 8 * 1024 * 1024)?;
        let diagnostics = read_tail(&scratch.path().join("stderr.log"));
        let version = help
            .lines()
            .chain(diagnostics.lines())
            .find(|s| s.starts_with("Volatility 3 Framework"))
            .ok_or("The executable did not identify itself as Volatility 3")?
            .to_string();
        let plugins = parse_plugins(&help);
        if plugins.is_empty() {
            return Err("Volatility returned no plugins. Check its supporting files.".into());
        }
        Ok(Self {
            settings,
            version,
            plugins,
        })
    }

    pub fn prepare(
        &self,
        evidence: &Evidence,
        plugin: &str,
        arguments: Vec<String>,
        output_root: &Path,
    ) -> Result<Run> {
        if !self.plugins.iter().any(|p| p.id == plugin) {
            return Err("Select a plugin from this installation".into());
        }
        evidence.check_metadata()?;
        let id = Uuid::new_v4().to_string();
        let mut command = vec![
            self.settings.executable.display().to_string(),
            "-q".into(),
            "-r".into(),
            "json".into(),
        ];
        if self.settings.offline {
            command.push("--offline".into());
        }
        if !self.settings.symbols.as_os_str().is_empty() {
            command.extend(["-s".into(), self.settings.symbols.display().to_string()]);
        }
        command.extend([
            "-f".into(),
            evidence.path.display().to_string(),
            "-o".into(),
            output_root.join(&id).display().to_string(),
            plugin.into(),
        ]);
        command.extend(arguments.clone());
        Ok(Run {
            id,
            evidence_id: evidence.id.clone(),
            plugin: plugin.into(),
            arguments,
            command,
            engine_version: self.version.clone(),
            created_at: now(),
            started_at: None,
            finished_at: None,
            status: RunStatus::Queued,
            exit_code: None,
            row_count: 0,
            message: String::new(),
        })
    }

    pub fn help(&self, plugin: &str, cancel: &AtomicBool) -> Result<String> {
        if !self.plugins.iter().any(|p| p.id == plugin) {
            return Err("Unknown plugin".into());
        }
        let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
        let result = capture(
            &self.settings.executable,
            &[plugin.into(), "--help".into()],
            scratch.path(),
            cancel,
            Some(Duration::from_secs(60)),
        )?;
        if result.cancelled {
            return Err("Help request cancelled".into());
        }
        let text = read_text(&scratch.path().join("stdout.json"), 8 * 1024 * 1024)?;
        if result.exit_code != Some(0) {
            return Err(read_tail(&scratch.path().join("stderr.log")));
        }
        Ok(text)
    }

    pub fn execute(&self, run: &Run, directory: &Path, cancel: &AtomicBool) -> Outcome {
        let result = (|| {
            let (executable, arguments) = run
                .command
                .split_first()
                .ok_or("Analysis has no command".to_string())?;
            let captured = capture(Path::new(executable), arguments, directory, cancel, None)?;
            let diagnostics = read_tail(&directory.join("stderr.log"));
            if captured.cancelled {
                return Ok(Outcome {
                    status: RunStatus::Cancelled,
                    exit_code: captured.exit_code,
                    message: "Analysis cancelled. Partial output is retained.".into(),
                    table: None,
                });
            }
            if captured.exit_code != Some(0) {
                return Ok(Outcome {
                    status: RunStatus::Failed,
                    exit_code: captured.exit_code,
                    message: if diagnostics.trim().is_empty() {
                        "Volatility exited without producing results. Inspect the raw output."
                            .into()
                    } else {
                        diagnostics
                    },
                    table: None,
                });
            }
            match Table::read(&directory.join("stdout.json")) {
                Ok(table) => Ok(Outcome {
                    status: RunStatus::Completed,
                    exit_code: captured.exit_code,
                    message: diagnostics,
                    table: Some(table),
                }),
                Err(error) => Ok(Outcome {
                    status: RunStatus::Failed,
                    exit_code: captured.exit_code,
                    message: format!(
                        "Volatility exited successfully but its JSON could not be loaded: {error}. Raw output is retained."
                    ),
                    table: None,
                }),
            }
        })();
        result.unwrap_or_else(|error: String| Outcome {
            status: RunStatus::Failed,
            exit_code: None,
            message: error,
            table: None,
        })
    }
}

pub struct Outcome {
    pub status: RunStatus,
    pub exit_code: Option<i32>,
    pub message: String,
    pub table: Option<Table>,
}

struct Captured {
    exit_code: Option<i32>,
    cancelled: bool,
}

fn capture(
    executable: &Path,
    arguments: &[String],
    directory: &Path,
    cancel: &AtomicBool,
    timeout: Option<Duration>,
) -> Result<Captured> {
    if cancel.load(Ordering::Relaxed) {
        return Ok(Captured {
            exit_code: None,
            cancelled: true,
        });
    }
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let stdout = File::create(directory.join("stdout.json")).map_err(|e| e.to_string())?;
    let stderr = File::create(directory.join("stderr.log")).map_err(|e| e.to_string())?;
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // Nuitka's executable must stay beside its supporting libraries.
    if let Some(parent) = executable.parent() {
        command.current_dir(parent);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot launch {}: {e}", executable.display()))?;
    #[cfg(windows)]
    let job = match ProcessJob::attach(&child) {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Captured {
                    exit_code: status.code(),
                    cancelled: false,
                });
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
        if cancel.load(Ordering::Relaxed) || timeout.is_some_and(|limit| start.elapsed() >= limit) {
            #[cfg(windows)]
            job.terminate();
            let _ = child.kill();
            let status = child.wait().map_err(|e| e.to_string())?;
            if !cancel.load(Ordering::Relaxed) {
                return Err("Volatility did not respond within 60 seconds".into());
            }
            return Ok(Captured {
                exit_code: status.code(),
                cancelled: true,
            });
        }
        thread::sleep(Duration::from_millis(40));
    }
}

// Closing this owned Windows handle also terminates descendants if VolGUI exits.
#[cfg(windows)]
struct ProcessJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl ProcessJob {
    fn attach(child: &std::process::Child) -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::*;
        // SAFETY: the job is unnamed, pointers refer to initialized structures, and the child
        // handle is borrowed only for this call. ProcessJob owns and closes the job handle.
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(format!(
                    "Cannot create process job: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let job = Self(handle);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                return Err(format!(
                    "Cannot configure process job: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if AssignProcessToJobObject(handle, child.as_raw_handle()) == 0 {
                // A very short help command may already have exited before assignment.
                let mut code = 0;
                if windows_sys::Win32::System::Threading::GetExitCodeProcess(
                    child.as_raw_handle(),
                    &mut code,
                ) == 0
                    || code == 259
                {
                    return Err(format!(
                        "Cannot attach Volatility to process job: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(job)
        }
    }

    fn terminate(&self) {
        // SAFETY: self holds a valid owned job handle.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessJob {
    fn drop(&mut self) {
        // SAFETY: this handle is closed exactly once by its owner.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub fn parse_plugins(help: &str) -> Vec<Plugin> {
    let mut plugins: Vec<Plugin> = vec![];
    let mut active = false;
    for line in help.lines() {
        if line.trim() == "PLUGIN" {
            active = true;
            continue;
        }
        if !active || line.trim().is_empty() {
            continue;
        }
        let trimmed = line.trim();
        let token = trimmed.split_whitespace().next().unwrap_or_default();
        if line.starts_with("    ")
            && !line.starts_with("     ")
            && token.contains('.')
            && !token.ends_with('.')
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
        {
            plugins.push(Plugin {
                id: token.into(),
                description: trimmed[token.len()..].trim().into(),
            });
        } else if let Some(plugin) = plugins.last_mut()
            && line.starts_with("      ")
        {
            if !plugin.description.is_empty() {
                plugin.description.push(' ');
            }
            plugin.description.push_str(trimmed);
        }
    }
    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    plugins.dedup_by(|a, b| a.id == b.id);
    plugins
}

/// Quotes group spaces. Backslash runs before a quote follow Windows argument rules;
/// other backslashes, including UNC path prefixes, remain literal.
pub fn parse_arguments(text: &str) -> Result<Vec<String>> {
    let mut args = vec![];
    let mut current = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' {
                let mut count = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    count += 1;
                }
                if chars.peek() == Some(&q) {
                    current.extend(std::iter::repeat_n('\\', count / 2));
                    chars.next();
                    if count % 2 == 1 {
                        current.push(q);
                    } else {
                        quote = None;
                    }
                } else {
                    current.extend(std::iter::repeat_n('\\', count));
                }
            } else {
                current.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            started = true;
        } else if c.is_whitespace() {
            if started {
                args.push(std::mem::take(&mut current));
                started = false;
            }
        } else {
            current.push(c);
            started = true;
        }
    }
    if quote.is_some() {
        return Err("Close the quote in plugin arguments".into());
    }
    if started {
        args.push(current);
    }
    Ok(args)
}

pub fn format_arguments(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| {
            let mut quoted = String::from("\"");
            let mut slashes = 0;
            for c in argument.chars() {
                if c == '\\' {
                    slashes += 1;
                    continue;
                }
                quoted.extend(std::iter::repeat_n(
                    '\\',
                    if c == '"' { slashes * 2 + 1 } else { slashes },
                ));
                quoted.push(c);
                slashes = 0;
            }
            quoted.extend(std::iter::repeat_n('\\', slashes * 2));
            quoted.push('"');
            quoted
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug)]
pub struct Record {
    pub fields: BTreeMap<String, Value>,
    pub depth: usize,
}

impl Record {
    pub fn text(&self, column: &str) -> String {
        self.fields
            .get(column)
            .map(display_value)
            .unwrap_or_default()
    }
    pub fn title(&self) -> String {
        for column in [
            "ImageFileName",
            "COMM",
            "Process",
            "Name",
            "FileName",
            "Variable",
            "Data",
            "PID",
        ] {
            if let Some(value) = self.fields.get(column) {
                return display_value(value);
            }
        }
        self.fields
            .values()
            .next()
            .map(display_value)
            .unwrap_or_else(|| "Artifact".into())
    }
}

pub fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "N/A".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[derive(Clone, Debug, Default)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Record>,
}

impl Table {
    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(&read_text(path, 128 * 1024 * 1024)?)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim_start_matches('\u{feff}').trim();
        let text = if text.starts_with("Volatility 3 Framework") {
            text.split_once('\n').map_or(text, |(_, rest)| rest.trim())
        } else {
            text
        };
        let value: Value = serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {e}"))?;
        let nodes = value.as_array().ok_or("Expected a Volatility JSON array")?;
        let mut rows = vec![];
        let mut columns = BTreeSet::new();
        fn visit(
            nodes: &[Value],
            depth: usize,
            rows: &mut Vec<Record>,
            columns: &mut BTreeSet<String>,
        ) -> Result<()> {
            if depth > 100 {
                return Err("Result hierarchy exceeds 100 levels".into());
            }
            for node in nodes {
                if rows.len() >= 1_000_000 {
                    return Err(
                        "Result exceeds one million records. Use plugin filters to narrow output."
                            .into(),
                    );
                }
                let object = node.as_object().ok_or("Expected an artifact object")?;
                let fields: BTreeMap<_, _> = object
                    .iter()
                    .filter(|(k, _)| k.as_str() != "__children")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                columns.extend(fields.keys().cloned());
                rows.push(Record { fields, depth });
                if let Some(children) = object.get("__children") {
                    visit(
                        children.as_array().ok_or("Invalid __children array")?,
                        depth + 1,
                        rows,
                        columns,
                    )?;
                }
            }
            Ok(())
        }
        visit(nodes, 0, &mut rows, &mut columns)?;
        let mut columns: Vec<_> = columns.into_iter().collect();
        let preferred = [
            "ImageFileName",
            "COMM",
            "PID",
            "PPID",
            "Name",
            "Variable",
            "Value",
            "Data",
        ];
        columns.sort_by_key(|c| {
            preferred
                .iter()
                .position(|p| p == c)
                .unwrap_or(preferred.len())
        });
        Ok(Self { columns, rows })
    }

    pub fn matching(&self, query: &str, sort: Option<(&str, bool)>) -> Vec<usize> {
        let query = query.to_lowercase();
        let mut indexes: Vec<_> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                query.is_empty()
                    || row
                        .fields
                        .values()
                        .any(|v| display_value(v).to_lowercase().contains(&query))
            })
            .map(|(index, _)| index)
            .collect();
        if let Some((column, descending)) = sort {
            indexes.sort_by(|a, b| {
                let a = self.rows[*a].fields.get(column);
                let b = self.rows[*b].fields.get(column);
                let order = match (a.and_then(Value::as_i64), b.and_then(Value::as_i64)) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    _ => match (a.and_then(Value::as_f64), b.and_then(Value::as_f64)) {
                        (Some(a), Some(b)) => a.total_cmp(&b),
                        _ => a.map(display_value).cmp(&b.map(display_value)),
                    },
                };
                if descending { order.reverse() } else { order }
            });
        }
        indexes
    }

    pub fn csv(&self, indexes: &[usize]) -> String {
        fn cell(value: &str, protect_formula: bool) -> String {
            let prefix = if protect_formula && value.trim_start().starts_with(['=', '+', '-', '@'])
            {
                "'"
            } else {
                ""
            };
            format!("\"{prefix}{}\"", value.replace('"', "\"\""))
        }
        let mut csv = self
            .columns
            .iter()
            .map(|c| cell(c, true))
            .collect::<Vec<_>>()
            .join(",");
        csv.push_str("\r\n");
        for &index in indexes {
            if let Some(row) = self.rows.get(index) {
                csv.push_str(
                    &self
                        .columns
                        .iter()
                        .map(|c| {
                            let value = row.fields.get(c);
                            cell(
                                &value.map(display_value).unwrap_or_default(),
                                value.is_some_and(Value::is_string),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                );
                csv.push_str("\r\n");
            }
        }
        csv
    }
}

pub fn read_text(path: &Path, limit: u64) -> Result<String> {
    let file = File::open(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    if file.metadata().map_err(|e| e.to_string())?.len() > limit {
        return Err(format!(
            "Output exceeds the {} MiB viewer limit",
            limit / 1024 / 1024
        ));
    }
    let mut text = String::new();
    file.take(limit + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > limit {
        return Err("Output grew beyond the viewer limit".into());
    }
    Ok(text)
}

pub fn read_tail(path: &Path) -> String {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map_or(0, |m| m.len());
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(16 * 1024)));
    let mut bytes = vec![];
    let _ = file.take(16 * 1024).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}
