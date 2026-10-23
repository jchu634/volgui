mod views;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use gpui_kit::{
    assets::IconName,
    component::{
        ActiveTheme, Disableable, Icon, Selectable, Sizable, TitleBar,
        button::{Button, ButtonVariants},
        input::{Input, InputEvent, InputState, Textarea, TextareaState},
    },
    prelude::FluentBuilder,
    *,
};
use volgui_again::{
    case::{Case, Evidence, RunStatus, now},
    settings::Settings,
    volatility::{Installation, Outcome, Table, display_value, format_arguments, parse_arguments},
};

const PAGE_SIZE: usize = 100;
fn key(kind: &str, id: &str) -> ElementId {
    SharedString::from(format!("{kind}-{id}")).into()
}
const CATEGORIES: &[(&str, &str, IconName)] = &[
    ("Processes", "windows.pslist.PsList", IconName::Cpu),
    ("Process tree", "windows.pstree.PsTree", IconName::GitBranch),
    ("Network", "windows.netscan.NetScan", IconName::Network),
    (
        "Files & handles",
        "windows.handles.Handles",
        IconName::Folder,
    ),
    (
        "Registry",
        "windows.registry.hivelist.HiveList",
        IconName::Database,
    ),
    (
        "Memory scan",
        "windows.malware.malfind.Malfind",
        IconName::Shield,
    ),
    ("System information", "windows.info.Info", IconName::Info),
    (
        "Command lines",
        "windows.cmdline.CmdLine",
        IconName::Terminal,
    ),
    (
        "Loaded modules",
        "windows.dlllist.DllList",
        IconName::Layers,
    ),
    ("File scan", "windows.filescan.FileScan", IconName::File),
    (
        "User sessions",
        "windows.sessions.Sessions",
        IconName::Users,
    ),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Welcome,
    NewCase,
    Workspace,
    Analyses,
    Bookmarks,
    CaseInfo,
    Settings,
    Plugins,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Overview,
    Raw,
    Notes,
    Diagnostics,
}

enum Event {
    Validated(std::result::Result<Installation, String>),
    Imported(Vec<std::result::Result<Evidence, String>>),
    Verified(String, std::result::Result<Evidence, String>),
    Progress(String),
    Finished(String, Outcome),
    Loaded(String, std::result::Result<Table, String>),
    Help(std::result::Result<String, String>),
    Exported(std::result::Result<PathBuf, String>),
}

struct Busy {
    label: String,
    cancel: Arc<AtomicBool>,
    run_id: Option<String>,
    started: Instant,
    displayed_seconds: u64,
}
impl Drop for Busy {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

pub struct Workspace {
    settings: Settings,
    installation: Option<Installation>,
    case: Option<Case>,
    view: View,
    detail: DetailTab,
    selected_evidence: Option<String>,
    selected_run: Option<String>,
    selected_row: Option<usize>,
    table: Option<Arc<Table>>,
    cache: HashMap<String, Arc<Table>>,
    indexes: Vec<usize>,
    sort: Option<(String, bool)>,
    page: usize,
    sidebar_visible: bool,
    busy: Option<Busy>,
    loading: Option<String>,
    pending_row: Option<(String, usize)>,
    queue_paused: bool,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    message: String,
    error: Option<String>,
    plugin: Option<String>,
    plugin_help: String,
    query: Entity<InputState>,
    plugin_query: Entity<InputState>,
    arguments: Entity<InputState>,
    note: Entity<TextareaState>,
    case_name: Entity<InputState>,
    case_directory: Entity<InputState>,
    engine_path: Entity<InputState>,
    symbol_path: Entity<InputState>,
    offline: bool,
    _subscriptions: Vec<Subscription>,
}

fn field(
    value: impl Into<SharedString>,
    placeholder: &'static str,
    window: &mut Window,
    cx: &mut App,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .default_value(value)
            .placeholder(placeholder)
    })
}

fn heading(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .text_xs()
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(cx.theme().muted_foreground)
        .child(text.into())
}

fn section(title: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(cx.theme().border)
        .child(div().font_weight(FontWeight::SEMIBOLD).child(title.into()))
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / (1024. * 1024. * 1024.))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024. * 1024.))
    } else {
        format!("{bytes} bytes")
    }
}

impl Workspace {
    pub fn new(
        engine: Option<PathBuf>,
        case_path: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        window.set_window_title("VolGUI");
        let loaded = Settings::load();
        let error = loaded.as_ref().err().cloned();
        let mut settings = loaded.unwrap_or_default();
        if let Some(engine) = engine {
            settings.executable = engine;
        }
        let (tx, rx) = mpsc::channel();
        let query = field("", "Search all artifact fields...", window, cx);
        let plugin_query = field("", "Find a plugin, OS or capability...", window, cx);
        let subscriptions = vec![
            cx.subscribe(&query, |this, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    if !this.save_note(cx) {
                        return;
                    }
                    this.page = 0;
                    this.refilter(cx);
                    cx.notify();
                }
            }),
            cx.subscribe(&plugin_query, |_, _, _: &InputEvent, cx| cx.notify()),
        ];
        let mut this = Self {
            engine_path: field(
                settings.executable.display().to_string(),
                "Path to vol.exe or its installation directory",
                window,
                cx,
            ),
            symbol_path: field(
                settings.symbols.display().to_string(),
                "Optional symbols directory",
                window,
                cx,
            ),
            offline: settings.offline,
            settings,
            installation: None,
            case: None,
            view: View::Welcome,
            detail: DetailTab::Overview,
            selected_evidence: None,
            selected_run: None,
            selected_row: None,
            table: None,
            cache: HashMap::new(),
            indexes: vec![],
            sort: None,
            page: 0,
            sidebar_visible: true,
            busy: None,
            loading: None,
            pending_row: None,
            queue_paused: false,
            tx,
            rx,
            message: "Ready".into(),
            error,
            plugin: None,
            plugin_help: String::new(),
            query,
            plugin_query,
            arguments: field("", "e.g. --pid 3488", window, cx),
            note: cx.new(|cx| {
                TextareaState::new(window, cx)
                    .placeholder("Record your observations about this artifact...")
            }),
            case_name: field("", "Case name", window, cx),
            case_directory: field("", "Choose a new case directory", window, cx),
            _subscriptions: subscriptions,
        };
        if let Some(path) = case_path {
            this.open_case(path, window, cx);
        }
        if !this.settings.executable.as_os_str().is_empty() {
            this.validate_engine(cx);
        }
        cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let alive =
                    cx.update(|window, cx| this.update(cx, |this, cx| this.poll(window, cx)));
                if !matches!(alive, Ok(Ok(()))) {
                    break;
                }
            }
        })
        .detach();
        cx.on_app_quit(|this, cx| {
            this.save_note(cx);
            if let Some(busy) = &this.busy {
                busy.cancel.store(true, Ordering::Relaxed);
            }
            async {}
        })
        .detach();
        this
    }

    fn can_switch(&self) -> bool {
        self.busy.is_none() && self.loading.is_none()
    }

    fn has_queued(&self) -> bool {
        self.case.as_ref().is_some_and(|c| {
            c.document
                .runs
                .iter()
                .any(|r| r.status == RunStatus::Queued)
        })
    }

    fn start(&mut self, label: &str, run_id: Option<String>) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        self.busy = Some(Busy {
            label: label.into(),
            cancel: cancel.clone(),
            run_id,
            started: Instant::now(),
            displayed_seconds: 0,
        });
        self.message = label.into();
        self.error = None;
        cancel
    }

    fn validate_engine(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.has_queued() {
            return;
        }
        let settings = Settings {
            executable: PathBuf::from(self.engine_path.read(cx).value().trim()),
            symbols: PathBuf::from(self.symbol_path.read(cx).value().trim()),
            offline: self.offline,
            recent_cases: self.settings.recent_cases.clone(),
        };
        let cancel = self.start("Checking Volatility installation", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Validated(Installation::discover(settings, &cancel)));
        });
        cx.notify();
    }

    fn open_case(&mut self, path: PathBuf, window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_switch() {
            self.error = Some("Wait for background work to finish before switching cases".into());
            return;
        }
        if !self.save_note(cx) {
            return;
        }
        if self.case.as_ref().is_some_and(|case| {
            path.canonicalize().ok().is_some_and(|p| {
                p == case.directory || p == case.directory.join(volgui_again::case::MANIFEST)
            })
        }) {
            self.view = View::Workspace;
            cx.notify();
            return;
        }
        match Case::open(&path) {
            Ok(case) => self.use_case(case, window, cx),
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    fn use_case(&mut self, case: Case, window: &mut Window, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        window.set_window_title(&format!("{} | VolGUI", case.document.name));
        self.selected_evidence = case.document.evidence.first().map(|e| e.id.clone());
        let recent = case.directory.join(volgui_again::case::MANIFEST);
        self.case = Some(case);
        self.cache.clear();
        self.table = None;
        self.indexes.clear();
        self.selected_run = None;
        self.selected_row = None;
        self.loading = None;
        self.error = None;
        self.pending_row = None;
        self.queue_paused = false;
        self.view = View::Workspace;
        self.message = "Case saved locally. Original evidence is referenced in place.".into();
        if let Err(error) = self.settings.remember(recent) {
            self.error = Some(error);
        }
        let id = self
            .case
            .as_ref()
            .unwrap()
            .document
            .runs
            .iter()
            .rev()
            .find(|r| r.status == RunStatus::Completed)
            .map(|r| r.id.clone());
        if let Some(id) = id {
            self.select_run(id, window, cx);
        }
    }

    fn create_case(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_switch() {
            return;
        }
        let directory = PathBuf::from(self.case_directory.read(cx).value().trim());
        if directory.as_os_str().is_empty() {
            self.error = Some("Choose a case directory".into());
            return;
        }
        match Case::create(&directory, self.case_name.read(cx).value().as_ref()) {
            Ok(case) => self.use_case(case, window, cx),
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    fn choose_path(&mut self, purpose: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        let directories = matches!(purpose, "directory" | "symbols");
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: !directories,
            directories,
            multiple: purpose == "evidence",
            prompt: Some(
                match purpose {
                    "open" => "Open case.volgui.json",
                    "evidence" => "Add memory images",
                    "engine" => "Choose Volatility executable",
                    "symbols" => "Choose symbols directory",
                    _ => "Choose case directory",
                }
                .into(),
            ),
        });
        cx.spawn_in(window, async move |this, cx| match receiver.await {
            Ok(Ok(Some(paths))) => {
                let _ = cx.update(|window, cx| {
                    this.update(cx, |this, cx| {
                        if paths.is_empty() {
                            return;
                        }
                        let path = &paths[0];
                        match purpose {
                            "open" => this.open_case(path.clone(), window, cx),
                            "evidence" => this.import(paths, cx),
                            _ => {
                                let input = match purpose {
                                    "engine" => &this.engine_path,
                                    "symbols" => &this.symbol_path,
                                    _ => &this.case_directory,
                                };
                                input.update(cx, |state, cx| {
                                    state.set_value(path.display().to_string(), window, cx)
                                });
                            }
                        }
                        cx.notify();
                    })
                });
            }
            Ok(Err(error)) => {
                let _ = this.update(cx, |this, cx| {
                    this.error = Some(error.to_string());
                    cx.notify();
                });
            }
            _ => {}
        })
        .detach();
    }

    fn import(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        if self.case.is_none() || self.busy.is_some() {
            return;
        }
        if !self.save_note(cx) {
            return;
        }
        let cancel = self.start("Hashing evidence", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut results = vec![];
            for path in paths {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let mut last = Instant::now() - Duration::from_secs(1);
                let result = Evidence::inspect(&path, &cancel, |bytes, total| {
                    if last.elapsed() > Duration::from_millis(200) {
                        let _ = tx.send(Event::Progress(format!(
                            "Hashing {} · {:.0}%",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            bytes as f64 / total as f64 * 100.
                        )));
                        last = Instant::now();
                    }
                });
                results.push(result);
            }
            let _ = tx.send(Event::Imported(results));
        });
        cx.notify();
    }

    fn verify(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        let Some(evidence) = self.evidence().cloned() else {
            return;
        };
        let cancel = self.start("Verifying evidence SHA-256", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut last = Instant::now() - Duration::from_secs(1);
            let result = Evidence::inspect(&evidence.path, &cancel, |bytes, total| {
                if last.elapsed() > Duration::from_millis(200) {
                    let _ = tx.send(Event::Progress(format!(
                        "Verifying SHA-256 · {:.0}%",
                        bytes as f64 / total as f64 * 100.
                    )));
                    last = Instant::now();
                }
            });
            let _ = tx.send(Event::Verified(evidence.id, result));
        });
        cx.notify();
    }

    fn evidence(&self) -> Option<&Evidence> {
        self.case
            .as_ref()?
            .document
            .evidence
            .iter()
            .find(|e| Some(&e.id) == self.selected_evidence.as_ref())
    }

    fn queue_analysis(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy.as_ref().is_some_and(|b| b.run_id.is_none()) {
            return;
        }
        let result = (|| {
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure and validate Volatility in settings")?;
            let evidence = self
                .evidence()
                .ok_or("Add and select a memory image first")?;
            let case = self.case.as_ref().ok_or("Create or open a case first")?;
            let plugin = self.plugin.as_ref().ok_or("Select a plugin")?;
            let arguments = parse_arguments(self.arguments.read(cx).value().as_ref())?;
            let run = engine.prepare(
                evidence,
                plugin,
                arguments,
                &case.directory.join("analyses"),
            )?;
            self.case.as_mut().unwrap().queue(run)?;
            Ok::<_, String>(())
        })();
        match result {
            Ok(()) => {
                self.view = View::Analyses;
                self.message = "Analysis queued".into();
                self.start_next(window, cx);
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    fn start_next(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.queue_paused {
            return;
        }
        let Some(engine) = self.installation.clone() else {
            return;
        };
        let Some(case) = self.case.as_mut() else {
            return;
        };
        let Some(index) = case
            .document
            .runs
            .iter()
            .position(|r| r.status == RunStatus::Queued)
        else {
            return;
        };
        let evidence_id = case.document.runs[index].evidence_id.clone();
        if let Some(evidence) = case.document.evidence.iter().find(|e| e.id == evidence_id)
            && let Err(error) = evidence.check_metadata()
        {
            let run = &mut case.document.runs[index];
            run.status = RunStatus::Failed;
            run.message = error.clone();
            run.finished_at = Some(now());
            if let Err(save) = case.save() {
                self.error = Some(save);
            } else {
                self.error = Some(error);
            }
            cx.notify();
            return;
        }
        case.document.runs[index].status = RunStatus::Running;
        case.document.runs[index].started_at = Some(now());
        if let Err(error) = case.save() {
            case.document.runs[index].status = RunStatus::Queued;
            case.document.runs[index].started_at = None;
            self.error = Some(error);
            self.queue_paused = true;
            cx.notify();
            return;
        }
        let run = case.document.runs[index].clone();
        let directory = case.run_dir(&run.id);
        let cancel = self.start(&format!("Running {}", run.plugin), Some(run.id.clone()));
        let tx = self.tx.clone();
        thread::spawn(move || {
            let outcome = engine.execute(&run, &directory, &cancel);
            let _ = tx.send(Event::Finished(run.id, outcome));
        });
        cx.notify();
    }

    fn poll(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(event) = self.rx.try_recv() {
            changed = true;
            match event {
                Event::Progress(text) => {
                    self.message = text;
                }
                Event::Validated(result) => {
                    self.busy = None;
                    match result {
                        Ok(engine) => {
                            self.message = format!(
                                "{} · {} plugins available",
                                engine.version,
                                engine.plugins.len()
                            );
                            self.settings = engine.settings.clone();
                            self.engine_path.update(cx, |state, cx| {
                                state.set_value(
                                    self.settings.executable.display().to_string(),
                                    window,
                                    cx,
                                )
                            });
                            if let Err(error) = self.settings.save() {
                                self.error = Some(error);
                            }
                            self.installation = Some(engine);
                        }
                        Err(error) => {
                            self.installation = None;
                            self.error = Some(error);
                        }
                    }
                }
                Event::Imported(results) => {
                    self.busy = None;
                    let mut added = 0;
                    let mut failures = vec![];
                    if let Some(case) = &mut self.case {
                        for result in results {
                            match result.and_then(|evidence| {
                                let id = evidence.id.clone();
                                case.add_evidence(evidence).map(|_| id)
                            }) {
                                Ok(id) => {
                                    self.selected_evidence = Some(id);
                                    added += 1;
                                }
                                Err(error) => failures.push(error),
                            }
                        }
                    }
                    self.message = format!("Added {added} evidence file(s). SHA-256 recorded.");
                    if added > 0 {
                        self.selected_run = None;
                        self.selected_row = None;
                        self.table = None;
                        self.indexes.clear();
                        self.view = View::Workspace;
                    }
                    if !failures.is_empty() {
                        self.error = Some(failures.join("\n"));
                    }
                }
                Event::Verified(id, result) => {
                    self.busy = None;
                    let checked = result.and_then(|current| {
                        self.case
                            .as_mut()
                            .ok_or("No case open".to_string())?
                            .record_verification(&id, &current)
                    });
                    match checked {
                        Ok(true) => {
                            self.message = "SHA-256 matches the imported evidence".into();
                        },
                        Ok(false) => self.error = Some("Evidence integrity mismatch. The file no longer matches its imported SHA-256.".into()),
                        Err(error) => self.error = Some(error),
                    }
                }
                Event::Finished(id, outcome) => {
                    self.busy = None;
                    if let Some(case) = &mut self.case
                        && let Err(error) = case.finish(&id, &outcome)
                    {
                        self.error = Some(error);
                        self.queue_paused = true;
                    }
                    self.message = format!("Analysis {}", outcome.status.label().to_lowercase());
                    if let Some(table) = outcome.table {
                        self.cache_table(id.clone(), Arc::new(table));
                    }
                    if outcome.status == RunStatus::Failed {
                        self.error = Some(outcome.message.chars().take(1800).collect());
                    }
                    if self.selected_run.as_ref() == Some(&id) || self.selected_run.is_none() {
                        self.select_run(id, window, cx);
                    }
                }
                Event::Loaded(id, result) => {
                    if self.loading.as_ref() == Some(&id) {
                        self.loading = None;
                    }
                    match result {
                        Ok(table) => {
                            let table = Arc::new(table);
                            self.cache_table(id.clone(), table.clone());
                            if self.selected_run.as_ref() == Some(&id) {
                                self.table = Some(table);
                                self.refilter(cx);
                                let row = self
                                    .pending_row
                                    .take()
                                    .filter(|(run, _)| run == &id)
                                    .map(|(_, row)| row)
                                    .or_else(|| self.indexes.first().copied());
                                self.select_row(row, window, cx);
                                self.page = self
                                    .indexes
                                    .iter()
                                    .position(|i| Some(*i) == row)
                                    .unwrap_or(0)
                                    / PAGE_SIZE;
                            }
                        }
                        Err(error) => {
                            if self.selected_run.as_ref() == Some(&id) {
                                self.error = Some(error);
                            }
                        }
                    }
                }
                Event::Help(result) => {
                    self.busy = None;
                    match result {
                        Ok(help) => self.plugin_help = help,
                        Err(error) => self.error = Some(error),
                    }
                }
                Event::Exported(result) => match result {
                    Ok(path) => self.message = format!("Exported {}", path.display()),
                    Err(error) => self.error = Some(format!("Export failed: {error}")),
                },
            }
        }
        if self.busy.is_none() {
            self.start_next(window, cx);
        }
        if let Some(busy) = &mut self.busy {
            let seconds = busy.started.elapsed().as_secs();
            if seconds != busy.displayed_seconds {
                busy.displayed_seconds = seconds;
                changed = true;
            }
        }
        if changed {
            cx.notify();
        }
    }

    fn cache_table(&mut self, id: String, table: Arc<Table>) {
        if self.cache.len() >= 3
            && !self.cache.contains_key(&id)
            && let Some(evict) = self
                .cache
                .keys()
                .find(|k| Some(*k) != self.selected_run.as_ref())
                .cloned()
        {
            self.cache.remove(&evict);
        }
        self.cache.insert(id, table);
    }

    fn select_run(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        let Some(case) = &self.case else {
            return;
        };
        let Some(run) = case.document.runs.iter().find(|r| r.id == id) else {
            return;
        };
        let completed = run.status == RunStatus::Completed;
        let path = case.run_dir(&id).join("stdout.json");
        self.selected_evidence = Some(run.evidence_id.clone());
        self.selected_run = Some(id.clone());
        self.selected_row = None;
        self.table = None;
        self.pending_row = None;
        self.indexes.clear();
        self.page = 0;
        self.sort = None;
        self.detail = DetailTab::Overview;
        self.view = View::Workspace;
        self.query
            .update(cx, |state, cx| state.set_value("", window, cx));
        if let Some(table) = self.cache.get(&id).cloned() {
            self.table = Some(table);
            self.refilter(cx);
            self.select_row(self.indexes.first().copied(), window, cx);
        } else if completed {
            self.loading = Some(id.clone());
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Event::Loaded(id, Table::read(&path)));
            });
        }
        cx.notify();
    }

    fn select_row(&mut self, row: Option<usize>, window: &mut Window, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        self.selected_row = row;
        let note = self
            .selected_run
            .as_ref()
            .and_then(|run| self.case.as_ref()?.annotation(run, row?))
            .map(|a| a.note.clone())
            .unwrap_or_default();
        self.note
            .update(cx, |state, cx| state.set_value(note, window, cx));
        cx.notify();
    }

    fn refilter(&mut self, cx: &App) {
        self.indexes = self
            .table
            .as_ref()
            .map(|t| {
                t.matching(
                    self.query.read(cx).value().as_ref(),
                    self.sort.as_ref().map(|(c, d)| (c.as_str(), *d)),
                )
            })
            .unwrap_or_default();
        self.page = self
            .page
            .min(self.indexes.len().saturating_sub(1) / PAGE_SIZE);
        if self
            .selected_row
            .is_some_and(|row| !self.indexes.contains(&row))
        {
            self.selected_row = None;
        }
    }

    fn annotate(&mut self, toggle: bool, cx: &mut Context<Self>) {
        let (Some(case), Some(run), Some(row)) =
            (&mut self.case, &self.selected_run, self.selected_row)
        else {
            return;
        };
        let bookmarked = case.annotation(run, row).is_some_and(|a| a.bookmarked);
        let note = self.note.read(cx).value().to_string();
        if let Err(error) = case.annotate(
            run,
            row,
            if toggle { !bookmarked } else { bookmarked },
            note,
        ) {
            self.error = Some(error);
        } else {
            self.message = "Artifact annotation saved".into();
        }
        cx.notify();
    }

    fn save_note(&mut self, cx: &mut Context<Self>) -> bool {
        let (Some(case), Some(run), Some(row)) =
            (&mut self.case, &self.selected_run, self.selected_row)
        else {
            return true;
        };
        let old = case.annotation(run, row);
        let note = self.note.read(cx).value().to_string();
        if old.map_or("", |a| a.note.as_str()) == note {
            return true;
        }
        let bookmarked = old.is_some_and(|a| a.bookmarked);
        if let Err(error) = case.annotate(run, row, bookmarked, note) {
            self.error = Some(error);
            cx.notify();
            false
        } else {
            true
        }
    }

    fn choose_category(
        &mut self,
        plugin: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(id) = self.case.as_ref().and_then(|case| {
            case.document
                .runs
                .iter()
                .rev()
                .find(|r| {
                    r.plugin == plugin
                        && Some(&r.evidence_id) == self.selected_evidence.as_ref()
                        && r.status == RunStatus::Completed
                })
                .map(|r| r.id.clone())
        }) {
            self.select_run(id, window, cx);
        } else {
            self.plugin = Some(plugin.into());
            self.plugin_help.clear();
            self.view = View::Plugins;
        }
        cx.notify();
    }

    fn plugin_help(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        let (Some(engine), Some(plugin)) = (self.installation.clone(), self.plugin.clone()) else {
            return;
        };
        let cancel = self.start("Loading plugin options", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Help(engine.help(&plugin, &cancel)));
        });
        cx.notify();
    }

    fn export(&mut self, report: bool, window: &mut Window, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        let Some(case) = &self.case else {
            return;
        };
        if !report && self.table.is_none() {
            self.error = Some("Select completed results to export".into());
            return;
        }
        let document = case.document.clone();
        let directory = case.directory.clone();
        let table = self.table.clone();
        let indexes = self.indexes.clone();
        let tx = self.tx.clone();
        let receiver = cx.prompt_for_new_path(
            &case.directory,
            Some(if report {
                "case-report.html"
            } else {
                "artifacts.csv"
            }),
        );
        cx.spawn_in(window, async move |_, _| match receiver.await {
            Ok(Ok(Some(path))) => {
                thread::spawn(move || {
                    let result = (|| {
                        let content = if report {
                            document.report(&directory)?
                        } else {
                            table.unwrap().csv(&indexes)
                        };
                        document.export(&directory, &path, content.as_bytes())?;
                        Ok(path)
                    })();
                    let _ = tx.send(Event::Exported(result));
                });
            }
            Ok(Err(error)) => {
                let _ = tx.send(Event::Exported(Err(error.to_string())));
            }
            _ => {}
        })
        .detach();
    }

    fn cancel_run(&mut self, id: String, cx: &mut Context<Self>) {
        if let Some(busy) = &self.busy
            && busy.run_id.as_ref() == Some(&id)
        {
            busy.cancel.store(true, Ordering::Relaxed);
            self.message = "Cancelling analysis...".into();
            cx.notify();
            return;
        }
        if let Some(case) = &mut self.case {
            if let Some(run) = case
                .document
                .runs
                .iter_mut()
                .find(|r| r.id == id && r.status == RunStatus::Queued)
            {
                run.status = RunStatus::Cancelled;
                run.finished_at = Some(now());
                run.message = "Cancelled before starting".into();
            }
            if let Err(error) = case.save() {
                self.error = Some(error);
            }
        }
        cx.notify();
    }
}
