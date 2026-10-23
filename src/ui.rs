mod views;

use gpui_kit::{
    assets::IconName,
    component::{
        ActiveTheme, Disableable, Icon, Selectable, Sizable, TitleBar, WindowExt,
        button::{Button, ButtonVariants},
        input::{Input, InputEvent, InputState, Textarea, TextareaState},
        list::ListItem,
        menu::{DropdownMenu, PopupMenu, PopupMenuItem},
        progress::Progress,
        tree::{Tree, TreeItem, TreeState},
        v_virtual_list,
    },
    prelude::FluentBuilder,
    *,
};
use std::{
    collections::{HashMap, HashSet},
    ops::Range,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};
use volgui_again::{
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, RunStatus, now},
    results::{
        BrowserEntry, ProcessNode, Query, ResultIndex, ResultStore, StoredRecord, process_forest,
    },
    settings::Settings,
    volatility::{Installation, Outcome, display_value, format_arguments, parse_arguments},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Welcome,
    NewCase,
    Workspace,
    Analyses,
    Bookmarks,
    CaseInfo,
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
    Opened(std::result::Result<Case, String>),
    Validated(std::result::Result<Installation, String>),
    Imported(Vec<std::result::Result<Evidence, String>>),
    Verified(String, std::result::Result<Evidence, String>),
    Progress(String),
    Finished(String, Outcome),
    Indexed(
        u64,
        std::result::Result<(ResultIndex, Vec<StoredRecord>), String>,
    ),
    Rows(
        u64,
        Vec<i64>,
        std::result::Result<Vec<StoredRecord>, String>,
    ),
    Selected(u64, std::result::Result<Option<StoredRecord>, String>),
    Browser(
        u64,
        std::result::Result<(Vec<BrowserEntry>, Vec<ProcessNode>), String>,
    ),
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
    selected: Option<Arc<StoredRecord>>,
    scope: Vec<String>,
    scope_label: String,
    index: ResultIndex,
    row_cache: HashMap<i64, Arc<StoredRecord>>,
    inflight: HashSet<i64>,
    sort: Option<(String, bool)>,
    query_epoch: Arc<AtomicU64>,
    query_due: Option<Instant>,
    loading: bool,
    selection_epoch: u64,
    browser_group: ArtifactGroup,
    browser_entries: Rc<Vec<BrowserEntry>>,
    browser_sizes: Rc<Vec<Size<Pixels>>>,
    browser_tree: Entity<TreeState>,
    browser_tree_mode: bool,
    browser_epoch: u64,
    browser_due: Option<Instant>,
    browser_loading: bool,
    result_scroll: UniformListScrollHandle,
    sidebar_visible: bool,
    busy: Option<Busy>,
    queue_paused: bool,
    batch_total: usize,
    batch_finished: usize,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    message: String,
    error: Option<String>,
    plugin: Option<String>,
    plugin_help: String,
    plugin_os: OperatingSystem,
    query: Entity<InputState>,
    browser_query: Entity<InputState>,
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
fn key(kind: &str, id: &str) -> ElementId {
    SharedString::from(format!("{kind}-{id}")).into()
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
fn section(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(cx.theme().border)
        .child(div().font_weight(FontWeight::SEMIBOLD).child(text.into()))
}
fn format_bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", n as f64 / 1073741824.)
    } else {
        format!("{:.1} MiB", n as f64 / 1048576.)
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
        if let Some(e) = engine {
            settings.executable = e;
        }
        let (tx, rx) = mpsc::channel();
        let query = field("", "Search artifact fields...", window, cx);
        let browser_query = field("", "Filter artifacts...", window, cx);
        let plugin_query = field("", "Find a plugin...", window, cx);
        let browser_tree = cx.new(|cx| TreeState::new(cx));
        let subscriptions = vec![
            cx.subscribe(&query, |this, _, e: &InputEvent, cx| {
                if matches!(e, InputEvent::Change) && this.save_note(cx) {
                    this.query_due = Some(Instant::now() + Duration::from_millis(180));
                    cx.notify();
                }
            }),
            cx.subscribe(&browser_query, |this, _, e: &InputEvent, cx| {
                if matches!(e, InputEvent::Change) {
                    this.browser_due = Some(Instant::now() + Duration::from_millis(180));
                    cx.notify();
                }
            }),
            cx.subscribe(&plugin_query, |_, _, _: &InputEvent, cx| cx.notify()),
            cx.observe(&browser_tree, |this, tree, cx| {
                let id = tree
                    .read(cx)
                    .selected_item()
                    .and_then(|i| i.id.strip_prefix("record-"))
                    .and_then(|s| s.parse::<i64>().ok());
                if let Some(id) = id
                    && this.selected.as_ref().is_none_or(|r| r.id != id)
                {
                    this.load_record(id, cx);
                }
            }),
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
            selected: None,
            scope: vec![],
            scope_label: "Artifacts".into(),
            index: ResultIndex::default(),
            row_cache: HashMap::new(),
            inflight: HashSet::new(),
            sort: None,
            query_epoch: Arc::new(AtomicU64::new(0)),
            query_due: None,
            loading: false,
            selection_epoch: 0,
            browser_group: ArtifactGroup::Processes,
            browser_entries: Rc::new(vec![]),
            browser_sizes: Rc::new(vec![]),
            browser_tree,
            browser_tree_mode: true,
            browser_epoch: 0,
            browser_due: None,
            browser_loading: false,
            result_scroll: UniformListScrollHandle::default(),
            sidebar_visible: true,
            busy: None,
            queue_paused: false,
            batch_total: 0,
            batch_finished: 0,
            tx,
            rx,
            message: "Ready".into(),
            error,
            plugin: None,
            plugin_help: String::new(),
            plugin_os: OperatingSystem::Windows,
            query,
            browser_query,
            plugin_query,
            arguments: field("", "e.g. --pid 3488", window, cx),
            note: cx.new(|cx| TextareaState::new(window, cx).placeholder("Investigator notes...")),
            case_name: field("", "Case name", window, cx),
            case_directory: field("", "Case directory", window, cx),
            _subscriptions: subscriptions,
        };
        if let Some(path) = case_path {
            this.open_case(path, window, cx);
        } else if !this.settings.executable.as_os_str().is_empty() {
            this.validate_engine(cx);
        }
        cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                if !matches!(
                    cx.update(|window, cx| this.update(cx, |this, cx| this.poll(window, cx))),
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        })
        .detach();
        cx.on_app_quit(|this, cx| {
            this.save_note(cx);
            if let Some(b) = &this.busy {
                b.cancel.store(true, Ordering::Relaxed);
            }
            async {}
        })
        .detach();
        this
    }
    fn can_switch(&self) -> bool {
        self.busy.is_none() && !self.has_queued()
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
    fn evidence(&self) -> Option<&Evidence> {
        self.case
            .as_ref()?
            .document
            .evidence
            .iter()
            .find(|e| Some(&e.id) == self.selected_evidence.as_ref())
    }
    fn store(&self) -> Option<ResultStore> {
        Some(ResultStore::at(&self.case.as_ref()?.directory))
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
        let cancel = self.start("Checking Volatility", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Validated(Installation::discover(settings, &cancel)));
        });
        cx.notify();
    }
    fn open_case(&mut self, path: PathBuf, _window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_switch() || !self.save_note(cx) {
            return;
        }
        if self.case.as_ref().is_some_and(|c| {
            path.canonicalize().ok().is_some_and(|p| {
                p == c.directory || p == c.directory.join(volgui_again::case::MANIFEST)
            })
        }) {
            self.view = View::Workspace;
            cx.notify();
            return;
        }
        let cancel = self.start("Opening case and indexing saved scans", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = Case::open(&path).and_then(|case| {
                case.document.migrate_results(&case.directory, &cancel)?;
                Ok(case)
            });
            let _ = tx.send(Event::Opened(result));
        });
        cx.notify();
    }
    fn use_case(&mut self, case: Case, window: &mut Window, cx: &mut Context<Self>) {
        self.query_epoch.fetch_add(1, Ordering::Relaxed);
        self.browser_epoch += 1;
        self.selection_epoch += 1;
        self.selected_evidence = case.document.evidence.first().map(|e| e.id.clone());
        let path = case.directory.join(volgui_again::case::MANIFEST);
        self.case = Some(case);
        self.selected = None;
        self.selected_run = None;
        self.selected_row = None;
        self.scope.clear();
        self.row_cache.clear();
        self.index = ResultIndex::default();
        self.queue_paused = false;
        self.batch_total = 0;
        self.batch_finished = 0;
        self.view = View::Workspace;
        self.message = "Case opened".into();
        window.set_window_title("VolGUI");
        if let Err(e) = self.settings.remember(path) {
            self.error = Some(e);
        }
        self.sync_os();
        self.refresh_browser(cx);
        if !self.group_runs(self.browser_group).is_empty() {
            self.choose_group(self.browser_group, window, cx);
        } else if let Some(id) = self
            .case
            .as_ref()
            .unwrap()
            .document
            .runs
            .iter()
            .rev()
            .find(|r| r.status == RunStatus::Completed)
            .map(|r| r.id.clone())
        {
            self.select_run(id, window, cx);
        }
    }
    fn sync_os(&mut self) {
        if let Some(os) = self
            .evidence()
            .map(|e| e.operating_system)
            .filter(|o| *o != OperatingSystem::Unknown)
        {
            self.plugin_os = os;
        }
    }
    fn create_case(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_switch() || !self.save_note(cx) {
            return;
        }
        let directory = PathBuf::from(self.case_directory.read(cx).value().trim());
        if directory.as_os_str().is_empty() {
            self.error = Some("Choose a case directory".into());
            return;
        }
        match Case::create(&directory, self.case_name.read(cx).value().as_ref()) {
            Ok(c) => self.use_case(c, window, cx),
            Err(e) => self.error = Some(e),
        }
        cx.notify();
    }
    fn choose_path(&mut self, purpose: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        let dirs = matches!(purpose, "directory" | "symbols");
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: !dirs,
            directories: dirs,
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
                        match purpose {
                            "open" => this.open_case(paths[0].clone(), window, cx),
                            "evidence" => this.import(paths, cx),
                            _ => {
                                let field = match purpose {
                                    "engine" => &this.engine_path,
                                    "symbols" => &this.symbol_path,
                                    _ => &this.case_directory,
                                };
                                field.update(cx, |s, cx| {
                                    s.set_value(paths[0].display().to_string(), window, cx)
                                });
                            }
                        }
                        cx.notify();
                    })
                });
            }
            Ok(Err(e)) => {
                let _ = this.update(cx, |this, cx| {
                    this.error = Some(e.to_string());
                    cx.notify();
                });
            }
            _ => {}
        })
        .detach();
    }
    fn import(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        if self.case.is_none() || self.busy.is_some() || !self.save_note(cx) {
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
                results.push(Evidence::inspect(&path, &cancel, |n, total| {
                    if last.elapsed() > Duration::from_millis(250) {
                        let _ = tx.send(Event::Progress(format!(
                            "Hashing {} · {:.0}%",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            n as f64 / total as f64 * 100.
                        )));
                        last = Instant::now();
                    }
                }));
            }
            let _ = tx.send(Event::Imported(results));
        });
        cx.notify();
    }
    fn verify(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        let Some(e) = self.evidence().cloned() else {
            return;
        };
        let cancel = self.start("Verifying evidence", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = Evidence::inspect(&e.path, &cancel, |_, _| {});
            let _ = tx.send(Event::Verified(e.id, result));
        });
        cx.notify();
    }
    fn set_os(&mut self, os: OperatingSystem, cx: &mut Context<Self>) {
        self.plugin_os = os;
        self.plugin = self.plugin.take().filter(|p| os.accepts(p));
        self.plugin_help.clear();
        if let Some(case) = &mut self.case {
            if let Some(e) = case
                .document
                .evidence
                .iter_mut()
                .find(|e| Some(&e.id) == self.selected_evidence.as_ref())
            {
                e.operating_system = os;
            }
            if let Err(e) = case.save() {
                self.error = Some(e);
            }
        }
        cx.notify();
    }
    fn queue_analysis(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy.as_ref().is_some_and(|b| b.run_id.is_none()) {
            return;
        }
        let result = (|| {
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure Volatility in settings")?;
            let evidence = self.evidence().ok_or("Select a memory image")?;
            let plugin = self.plugin.as_ref().ok_or("Select a plugin")?;
            if !self.plugin_os.accepts(plugin) {
                return Err("The plugin does not match the evidence OS".into());
            }
            let run = engine.prepare(
                evidence,
                plugin,
                parse_arguments(self.arguments.read(cx).value().as_ref())?,
                &self.case.as_ref().unwrap().directory.join("analyses"),
            )?;
            self.case.as_mut().unwrap().queue(run)?;
            Ok::<_, String>(())
        })();
        match result {
            Ok(()) => {
                if self.busy.is_none() && !self.has_queued() {
                    self.batch_total = 0;
                    self.batch_finished = 0;
                }
                if self.batch_total == self.batch_finished {
                    self.batch_total = 0;
                    self.batch_finished = 0;
                }
                self.batch_total += 1;
                self.message = "Analysis queued".into();
                self.start_next(window, cx);
                self.view = View::Workspace;
            }
            Err(e) => self.error = Some(e),
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
        let Some(case) = &mut self.case else {
            return;
        };
        let Some(i) = case
            .document
            .runs
            .iter()
            .position(|r| r.status == RunStatus::Queued)
        else {
            return;
        };
        let evidence = case
            .document
            .evidence
            .iter()
            .find(|e| e.id == case.document.runs[i].evidence_id)
            .unwrap();
        if let Err(e) = evidence.check_metadata() {
            case.document.runs[i].status = RunStatus::Failed;
            case.document.runs[i].message = e.clone();
            case.document.runs[i].finished_at = Some(now());
            self.error = Some(e);
            if let Err(e) = case.save() {
                self.error = Some(e);
                self.queue_paused = true;
            }
            self.batch_finished += 1;
            cx.notify();
            return;
        }
        case.document.runs[i].status = RunStatus::Running;
        case.document.runs[i].started_at = Some(now());
        if let Err(e) = case.save() {
            case.document.runs[i].status = RunStatus::Queued;
            self.error = Some(e);
            self.queue_paused = true;
            return;
        }
        let run = case.document.runs[i].clone();
        let directory = case.run_dir(&run.id);
        let store = ResultStore::at(&case.directory);
        let cancel = self.start(&format!("Running {}", run.plugin), Some(run.id.clone()));
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut outcome = engine.execute(&run, &directory, &cancel);
            if let Some(table) = outcome.table.take()
                && let Err(e) = store.insert_cancellable(&run, &table, &cancel)
            {
                outcome.status = if cancel.load(Ordering::Relaxed) {
                    RunStatus::Cancelled
                } else {
                    RunStatus::Failed
                };
                outcome.message =
                    format!("Could not save scan to SQLite: {e}. Raw output is retained.");
            }
            let _ = tx.send(Event::Finished(run.id, outcome));
        });
        cx.notify();
    }
    fn group_runs(&self, group: ArtifactGroup) -> Vec<String> {
        let Some(case) = &self.case else {
            return vec![];
        };
        let mut seen = HashSet::new();
        case.document
            .runs
            .iter()
            .rev()
            .filter(|r| {
                Some(&r.evidence_id) == self.selected_evidence.as_ref()
                    && r.status == RunStatus::Completed
                    && ArtifactGroup::for_plugin(&r.plugin) == group
            })
            .filter(|r| seen.insert(r.plugin.clone()))
            .map(|r| r.id.clone())
            .collect()
    }
    fn group_count(&self, group: ArtifactGroup) -> usize {
        let ids = self.group_runs(group);
        self.case.as_ref().map_or(0, |c| {
            c.document
                .runs
                .iter()
                .filter(|r| ids.contains(&r.id))
                .map(|r| r.row_count)
                .sum()
        })
    }
    fn select_evidence(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        self.selected_evidence = Some(id);
        self.sync_os();
        self.selected = None;
        self.selected_row = None;
        self.selected_run = None;
        self.scope.clear();
        self.index = ResultIndex::default();
        self.refresh_browser(cx);
        self.choose_group(self.browser_group, window, cx);
    }
    fn choose_group(&mut self, group: ArtifactGroup, window: &mut Window, cx: &mut Context<Self>) {
        let runs = self.group_runs(group);
        self.set_scope(runs, group.label().into(), window, cx);
    }
    fn set_browser(&mut self, group: ArtifactGroup, window: &mut Window, cx: &mut Context<Self>) {
        self.browser_group = group;
        self.browser_query
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.refresh_browser(cx);
        self.choose_group(group, window, cx);
    }
    fn select_run(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        let Some(run) = self
            .case
            .as_ref()
            .and_then(|c| c.document.runs.iter().find(|r| r.id == id))
            .cloned()
        else {
            return;
        };
        if Some(&run.evidence_id) != self.selected_evidence.as_ref() {
            self.selected_evidence = Some(run.evidence_id.clone());
            self.sync_os();
            self.refresh_browser(cx);
        }
        self.set_scope(vec![id], run.plugin, window, cx);
    }
    fn set_scope(
        &mut self,
        runs: Vec<String>,
        label: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.save_note(cx) {
            return;
        }
        self.scope = runs;
        self.scope_label = label;
        self.selected = None;
        self.selected_row = None;
        self.selected_run = self.scope.first().cloned();
        self.sort = None;
        self.index = ResultIndex::default();
        self.row_cache.clear();
        self.detail = DetailTab::Overview;
        self.view = View::Workspace;
        self.query.update(cx, |s, cx| s.set_value("", window, cx));
        self.query_due = None;
        self.result_scroll = UniformListScrollHandle::default();
        self.start_query(cx);
        cx.notify();
    }
    fn active_query(&self, cx: &App) -> Query {
        Query {
            runs: self.scope.clone(),
            text: self.query.read(cx).value().to_string(),
            sort: self.sort.clone(),
        }
    }
    fn start_query(&mut self, cx: &mut Context<Self>) {
        let Some(store) = self.store() else {
            return;
        };
        let query = self.active_query(cx);
        let epoch = self.query_epoch.fetch_add(1, Ordering::Relaxed) + 1;
        let token = self.query_epoch.clone();
        self.loading = true;
        self.inflight.clear();
        let tx = self.tx.clone();
        thread::spawn(move || {
            if token.load(Ordering::Relaxed) != epoch {
                return;
            }
            let result = store.query(&query).and_then(|index| {
                let rows = store.fetch(&index.ids[..index.ids.len().min(128)])?;
                Ok((index, rows))
            });
            let _ = tx.send(Event::Indexed(epoch, result));
        });
        cx.notify();
    }
    fn request_rows(&mut self, range: Range<usize>) {
        let Some(store) = self.store() else {
            return;
        };
        let ids: Vec<_> = self
            .index
            .ids
            .get(range.start.min(self.index.ids.len())..range.end.min(self.index.ids.len()))
            .unwrap_or(&[])
            .iter()
            .copied()
            .filter(|id| !self.row_cache.contains_key(id) && !self.inflight.contains(id))
            .take(256)
            .collect();
        if ids.is_empty() {
            return;
        }
        self.inflight.extend(&ids);
        let epoch = self.query_epoch.load(Ordering::Relaxed);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = store.fetch(&ids);
            let _ = tx.send(Event::Rows(epoch, ids, result));
        });
    }
    fn load_record(&mut self, id: i64, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        let Some(store) = self.store() else {
            return;
        };
        self.selection_epoch += 1;
        let epoch = self.selection_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Selected(
                epoch,
                store.fetch(&[id]).map(|mut r| r.pop()),
            ));
        });
    }
    fn load_annotation(&mut self, run: String, row: usize, cx: &mut Context<Self>) {
        if !self.save_note(cx) {
            return;
        }
        let Some(store) = self.store() else {
            return;
        };
        self.selection_epoch += 1;
        let epoch = self.selection_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Selected(epoch, store.record(&run, row)));
        });
    }
    fn show_record(&mut self, record: StoredRecord, window: &mut Window, cx: &mut Context<Self>) {
        self.selected_run = Some(record.run_id.clone());
        self.selected_row = Some(record.row);
        let note = self
            .case
            .as_ref()
            .and_then(|c| c.annotation(&record.run_id, record.row))
            .map(|a| a.note.clone())
            .unwrap_or_default();
        self.selected = Some(Arc::new(record));
        self.note.update(cx, |s, cx| s.set_value(note, window, cx));
        if self.browser_group == ArtifactGroup::Processes {
            let item = self
                .selected
                .as_ref()
                .map(|r| TreeItem::new(format!("record-{}", r.id), r.record.title()));
            self.browser_tree
                .update(cx, |tree, cx| tree.set_selected_item(item.as_ref(), cx));
        }
        cx.notify();
    }
    fn refresh_browser(&mut self, cx: &mut Context<Self>) {
        let Some(store) = self.store() else {
            return;
        };
        let mut runs = self.group_runs(self.browser_group);
        if self.browser_group == ArtifactGroup::Processes
            && let Some(c) = &self.case
        {
            runs.sort_by_key(|id| {
                c.document.runs.iter().find(|r| &r.id == id).map_or(3, |r| {
                    if r.plugin.contains(".pslist.") {
                        0
                    } else if r.plugin.contains(".pstree.") {
                        1
                    } else {
                        2
                    }
                })
            });
        }
        let query = Query {
            runs,
            text: self.browser_query.read(cx).value().to_string(),
            sort: None,
        };
        self.browser_epoch += 1;
        let epoch = self.browser_epoch;
        self.browser_loading = true;
        let tx = self.tx.clone();
        let processes = self.browser_group == ArtifactGroup::Processes;
        thread::spawn(move || {
            let result = store.navigation(&query).map(|mut entries| {
                if processes {
                    let mut seen = HashSet::new();
                    entries.retain(|e| e.pid.as_ref().is_none_or(|pid| seen.insert(pid.clone())));
                }
                let forest = if processes {
                    process_forest(&entries)
                } else {
                    vec![]
                };
                (entries, forest)
            });
            let _ = tx.send(Event::Browser(epoch, result));
        });
        cx.notify();
    }
    fn save_note(&mut self, cx: &mut Context<Self>) -> bool {
        let (Some(c), Some(run), Some(row)) =
            (&mut self.case, &self.selected_run, self.selected_row)
        else {
            return true;
        };
        let old = c.annotation(run, row);
        let note = self.note.read(cx).value().to_string();
        if old.map_or("", |a| a.note.as_str()) == note {
            return true;
        }
        let marked = old.is_some_and(|a| a.bookmarked);
        match c.annotate(run, row, marked, note) {
            Ok(()) => true,
            Err(e) => {
                self.error = Some(e);
                cx.notify();
                false
            }
        }
    }
    fn annotate(&mut self, toggle: bool, cx: &mut Context<Self>) {
        let (Some(c), Some(run), Some(row)) =
            (&mut self.case, &self.selected_run, self.selected_row)
        else {
            return;
        };
        let marked = c.annotation(run, row).is_some_and(|a| a.bookmarked);
        let note = self.note.read(cx).value().to_string();
        if let Err(e) = c.annotate(run, row, if toggle { !marked } else { marked }, note) {
            self.error = Some(e);
        } else {
            self.message = "Annotation saved".into();
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
        let Some(c) = &self.case else {
            return;
        };
        let document = c.document.clone();
        let directory = c.directory.clone();
        let query = self.active_query(cx);
        let tx = self.tx.clone();
        let receiver = cx.prompt_for_new_path(
            &directory,
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
                            ResultStore::at(&directory).export_csv(&query)?
                        };
                        document.export(&directory, &path, content.as_bytes())?;
                        Ok(path)
                    })();
                    let _ = tx.send(Event::Exported(result));
                });
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::Exported(Err(e.to_string())));
            }
            _ => {}
        })
        .detach();
    }
    fn cancel_run(&mut self, id: String, cx: &mut Context<Self>) {
        if let Some(b) = &self.busy
            && b.run_id.as_ref() == Some(&id)
        {
            b.cancel.store(true, Ordering::Relaxed);
            self.message = "Cancelling analysis...".into();
            cx.notify();
            return;
        }
        if let Some(c) = &mut self.case {
            if let Some(r) = c
                .document
                .runs
                .iter_mut()
                .find(|r| r.id == id && r.status == RunStatus::Queued)
            {
                r.status = RunStatus::Cancelled;
                r.finished_at = Some(now());
                self.batch_finished += 1;
            }
            if let Err(e) = c.save() {
                self.error = Some(e);
            }
        }
        cx.notify();
    }
    fn poll(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(event) = self.rx.try_recv() {
            changed = true;
            match event {
                Event::Opened(result) => {
                    self.busy = None;
                    match result {
                        Ok(c) => {
                            self.use_case(c, window, cx);
                            if self.installation.is_none()
                                && !self.settings.executable.as_os_str().is_empty()
                            {
                                self.validate_engine(cx);
                            }
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Validated(result) => {
                    self.busy = None;
                    match result {
                        Ok(engine) => {
                            self.settings = engine.settings.clone();
                            if let Err(e) = self.settings.save() {
                                self.error = Some(e);
                            }
                            self.message =
                                format!("{} · {} plugins", engine.version, engine.plugins.len());
                            self.installation = Some(engine);
                        }
                        Err(e) => {
                            self.installation = None;
                            self.error = Some(e);
                        }
                    }
                }
                Event::Progress(s) => self.message = s,
                Event::Imported(results) => {
                    self.busy = None;
                    let mut added = 0;
                    for result in results {
                        match result.and_then(|e| {
                            let id = e.id.clone();
                            self.case.as_mut().unwrap().add_evidence(e)?;
                            Ok(id)
                        }) {
                            Ok(id) => {
                                self.selected_evidence = Some(id);
                                added += 1;
                            }
                            Err(e) => self.error = Some(e),
                        }
                    }
                    if added > 0 {
                        self.selected = None;
                        self.selected_run = None;
                        self.selected_row = None;
                        self.scope.clear();
                        self.index = ResultIndex::default();
                        self.refresh_browser(cx);
                        self.view = View::Workspace;
                    }
                    self.message = format!("Added {added} evidence file(s)");
                }
                Event::Verified(id, result) => {
                    self.busy = None;
                    match result
                        .and_then(|e| self.case.as_mut().unwrap().record_verification(&id, &e))
                    {
                        Ok(true) => self.message = "Evidence SHA-256 matches".into(),
                        Ok(false) => self.error = Some("Evidence integrity mismatch".into()),
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Finished(id, outcome) => {
                    self.busy = None;
                    self.batch_finished += 1;
                    if let Some(c) = &mut self.case
                        && let Err(e) = c.finish(&id, &outcome)
                    {
                        self.error = Some(e);
                        self.queue_paused = true;
                    }
                    self.message = format!("Analysis {}", outcome.status.label().to_lowercase());
                    if outcome.status == RunStatus::Failed {
                        self.error = Some(outcome.message.chars().take(1500).collect());
                    }
                    self.refresh_browser(cx);
                    if self.scope.is_empty() || self.scope.contains(&id) {
                        self.select_run(id, window, cx);
                    }
                }
                Event::Indexed(epoch, result) => {
                    if epoch != self.query_epoch.load(Ordering::Relaxed) {
                        continue;
                    }
                    self.loading = false;
                    match result {
                        Ok((index, rows)) => {
                            self.index = index;
                            self.row_cache.clear();
                            for r in rows {
                                self.row_cache.insert(r.id, Arc::new(r));
                            }
                            if self.selected.is_none() {
                                if let Some(id) = self.index.ids.first().copied()
                                    && let Some(r) = self.row_cache.get(&id)
                                {
                                    self.show_record((**r).clone(), window, cx);
                                }
                            } else if self
                                .selected
                                .as_ref()
                                .is_some_and(|r| !self.index.ids.contains(&r.id))
                            {
                                self.selected = None;
                                self.selected_row = None;
                            }
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Rows(epoch, ids, result) => {
                    if epoch != self.query_epoch.load(Ordering::Relaxed) {
                        continue;
                    }
                    for id in ids {
                        self.inflight.remove(&id);
                    }
                    match result {
                        Ok(rows) => {
                            if self.row_cache.len() > 1024 {
                                self.row_cache.clear();
                            }
                            for r in rows {
                                self.row_cache.insert(r.id, Arc::new(r));
                            }
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Selected(epoch, result) => {
                    if epoch != self.selection_epoch {
                        continue;
                    }
                    match result {
                        Ok(Some(r)) => {
                            self.view = View::Workspace;
                            if !self.scope.contains(&r.run_id) {
                                let run = r.run_id.clone();
                                self.set_scope(
                                    vec![run.clone()],
                                    self.case
                                        .as_ref()
                                        .and_then(|c| c.document.runs.iter().find(|s| s.id == run))
                                        .map(|r| r.plugin.clone())
                                        .unwrap_or_default(),
                                    window,
                                    cx,
                                );
                            }
                            self.show_record(r, window, cx);
                        }
                        Ok(None) => {
                            self.error =
                                Some("Artifact no longer exists in the case database".into())
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Browser(epoch, result) => {
                    if epoch != self.browser_epoch {
                        continue;
                    }
                    self.browser_loading = false;
                    match result {
                        Ok((entries, forest)) => {
                            self.browser_sizes =
                                Rc::new(vec![size(px(240.), px(30.)); entries.len()]);
                            self.browser_entries = Rc::new(entries);
                            fn item(node: ProcessNode) -> TreeItem {
                                TreeItem::new(
                                    format!("record-{}", node.entry.id),
                                    format!(
                                        "{}  {}",
                                        node.entry.title,
                                        node.entry.pid.as_deref().unwrap_or("")
                                    ),
                                )
                                .expanded(false)
                                .children(node.children.into_iter().map(item))
                            }
                            let items = forest.into_iter().map(item).collect::<Vec<_>>();
                            self.browser_tree
                                .update(cx, |tree, cx| tree.set_items(items, cx));
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Help(result) => {
                    self.busy = None;
                    match result {
                        Ok(s) => self.plugin_help = s,
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::Exported(result) => match result {
                    Ok(p) => self.message = format!("Exported {}", p.display()),
                    Err(e) => self.error = Some(format!("Export failed: {e}")),
                },
            }
        }
        if self.query_due.is_some_and(|t| Instant::now() >= t) {
            self.query_due = None;
            self.start_query(cx);
            changed = true;
        }
        if self.browser_due.is_some_and(|t| Instant::now() >= t) {
            self.browser_due = None;
            self.refresh_browser(cx);
            changed = true;
        }
        if self.busy.is_none() {
            self.start_next(window, cx);
        }
        if let Some(b) = &mut self.busy {
            let seconds = b.started.elapsed().as_secs();
            if seconds != b.displayed_seconds {
                b.displayed_seconds = seconds;
                changed = true;
            }
        }
        if changed {
            cx.notify();
        }
    }
}
