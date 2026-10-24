// Owns shared workspace state and dispatches background events.
mod analysis_actions;
mod case_actions;
mod chrome;
mod exports;
mod file_actions;
mod navigation;
mod popups;
mod result_actions;
mod shell;
#[path = "views/mod.rs"]
mod views;

use gpui_kit::{
    assets::IconName,
    base::{Button as ActionButton, InteractiveElementExt, Link as TextLink, SelectableText},
    component::{
        ActiveTheme, Disableable, Icon, Selectable, Sizable, TitleBar, WindowExt,
        button::{Button, ButtonVariants},
        checkbox::Checkbox,
        input::{Input, InputEvent, InputState},
        list::ListItem,
        menu::{DropdownMenu, PopupMenu, PopupMenuItem},
        popover::Popover,
        progress::ProgressCircle,
        resizable::{HandleEdge, h_resizable, resizable_panel, resize_handle, v_resizable},
        scroll::{ScrollableElement, Scrollbar, ScrollbarMode},
        tooltip::Tooltip,
    },
    prelude::FluentBuilder,
    *,
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashMap, HashSet},
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
use volgui::{
    analyses::{AnalysisDraft, basic_label, chooser_plugins, queue_retries},
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, QueueClearScope, RunStatus, now},
    result_table as table,
    result_tree::ResultTree,
    results::{ProcessRelations, Query, ResultIndex, ResultStore, StoredRecord},
    settings::Settings,
    volatility::{Installation, Outcome, display_value, format_arguments},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    NewCase,
    Workspace,
    Analyses,
    Bookmarks,
    CaseInfo,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Overview,
    Raw,
    Diagnostics,
    Files,
}

struct FileDumpRequest {
    record_id: i64,
    selection_epoch: u64,
    executable: Option<PathBuf>,
    show_hex: bool,
}

#[derive(Default)]
enum HexView {
    #[default]
    Idle,
    Loading,
    Ready {
        files: Vec<PathBuf>,
        page: volgui::extracted_files::HexPage,
    },
    Error(String),
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
        std::result::Result<(ResultIndex, Vec<StoredRecord>, ResultTree), String>,
    ),
    Rows(
        u64,
        Vec<i64>,
        std::result::Result<Vec<StoredRecord>, String>,
    ),
    ColumnFitted(u64, u64, String, std::result::Result<Pixels, String>),
    Selected(u64, std::result::Result<Option<StoredRecord>, String>),
    Relations(u64, std::result::Result<ProcessRelations, String>),
    Help(String, std::result::Result<String, String>),
    Exported(std::result::Result<PathBuf, String>),
    HexLoaded(
        u64,
        std::result::Result<(Vec<PathBuf>, volgui::extracted_files::HexPage), String>,
    ),
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
    welcome_open: bool,
    view: View,
    back_stack: Vec<navigation::Location>,
    workspace_focus: FocusHandle,
    detail: DetailTab,
    selected_evidence: Option<String>,
    selected_run: Option<String>,
    selected_row: Option<usize>,
    selected: Option<Arc<StoredRecord>>,
    scope: Vec<String>,
    scope_label: String,
    index: ResultIndex,
    result_tree: ResultTree,
    tree_cursor: Option<usize>,
    row_cache: HashMap<i64, Arc<StoredRecord>>,
    inflight: HashSet<i64>,
    sort: Option<(String, bool)>,
    query_epoch: Arc<AtomicU64>,
    query_due: Option<Instant>,
    loading: bool,
    selection_epoch: u64,
    browser_group: ArtifactGroup,
    show_file_handles: bool,
    result_scroll: UniformListScrollHandle,
    table_x_scroll: ScrollHandle,
    details_scroll: ScrollHandle,
    queue_scroll: ScrollHandle,
    relations_scroll: UniformListScrollHandle,
    column_widths: HashMap<String, Pixels>,
    column_drag_origin: Rc<Cell<Pixels>>,
    column_fit_epoch: Arc<AtomicU64>,
    relations: ProcessRelations,
    relation_epoch: u64,
    raw_expanded: HashSet<String>,
    raw_expand_all: bool,
    queue_open: bool,
    popup_panels: RefCell<HashMap<popups::PanelKind, Entity<popups::PopupPanel>>>,
    file_dumps: HashMap<String, FileDumpRequest>,
    file_offset_physical: bool,
    hex_view: HexView,
    hex_visible: bool,
    hex_scroll: ScrollHandle,
    hex_epoch: u64,
    artifact_open: Option<ArtifactGroup>,
    artifact_choices: HashMap<ArtifactGroup, BTreeSet<String>>,
    analysis_group_filter: Option<ArtifactGroup>,
    analysis_collapsed_groups: std::collections::HashSet<ArtifactGroup>,
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
    analysis_drafts: Vec<AnalysisDraft>,
    analysis_active: usize,
    show_extended: bool,
    allow_previous_plugins: bool,
    analysis_error: Option<String>,
    query: Entity<InputState>,
    hex_offset: Entity<InputState>,
    plugin_query: Entity<InputState>,
    arguments: Entity<InputState>,
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
fn record_link(id: impl Into<ElementId>, text: impl Into<SharedString>, cx: &App) -> TextLink {
    TextLink::new(id)
        .text_color(cx.theme().link)
        .underline()
        .cursor_pointer()
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
        let plugin_query = field("", "Find a plugin...", window, cx);
        let arguments = field("", "e.g. --pid 3488", window, cx);
        let subscriptions = vec![
            cx.subscribe(&query, |this, _, e: &InputEvent, cx| {
                if matches!(e, InputEvent::Change) {
                    this.query_due = Some(Instant::now() + Duration::from_millis(180));
                    cx.notify();
                }
            }),
            cx.subscribe(&plugin_query, |_, _, _: &InputEvent, cx| cx.notify()),
            cx.subscribe(&arguments, |this, input, e: &InputEvent, cx| {
                if matches!(e, InputEvent::Change)
                    && let Some(id) = this.plugin.clone()
                    && let Some(draft) = this.analysis_drafts.get_mut(this.analysis_active)
                {
                    draft
                        .arguments
                        .insert(id, input.read(cx).value().to_string());
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
            welcome_open: false,
            view: View::Workspace,
            back_stack: Vec::new(),
            workspace_focus: cx.focus_handle(),
            detail: DetailTab::Overview,
            selected_evidence: None,
            selected_run: None,
            selected_row: None,
            selected: None,
            scope: vec![],
            scope_label: "Artifacts".into(),
            index: ResultIndex::default(),
            result_tree: ResultTree::default(),
            tree_cursor: None,
            row_cache: HashMap::new(),
            inflight: HashSet::new(),
            sort: None,
            query_epoch: Arc::new(AtomicU64::new(0)),
            query_due: None,
            loading: false,
            selection_epoch: 0,
            browser_group: ArtifactGroup::Processes,
            show_file_handles: true,
            result_scroll: UniformListScrollHandle::default(),
            table_x_scroll: ScrollHandle::default(),
            details_scroll: ScrollHandle::default(),
            queue_scroll: ScrollHandle::default(),
            relations_scroll: UniformListScrollHandle::default(),
            column_widths: HashMap::new(),
            column_drag_origin: Rc::new(Cell::new(px(0.))),
            column_fit_epoch: Arc::new(AtomicU64::new(0)),
            relations: ProcessRelations::default(),
            relation_epoch: 0,
            raw_expanded: HashSet::new(),
            raw_expand_all: false,
            queue_open: false,
            popup_panels: RefCell::new(HashMap::new()),
            file_dumps: HashMap::new(),
            file_offset_physical: false,
            hex_view: HexView::Idle,
            hex_visible: false,
            hex_scroll: ScrollHandle::default(),
            hex_epoch: 0,
            artifact_open: None,
            artifact_choices: HashMap::new(),
            analysis_group_filter: None,
            analysis_collapsed_groups: std::collections::HashSet::new(),
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
            analysis_drafts: Vec::new(),
            analysis_active: 0,
            show_extended: false,
            allow_previous_plugins: false,
            analysis_error: None,
            query,
            hex_offset: field("0x0", "Offset", window, cx),
            plugin_query,
            arguments,
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
        cx.on_app_quit(|this, _cx| {
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
                self.file_dumps.remove(&id);
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
                Event::Relations(epoch, result) => {
                    if epoch == self.relation_epoch {
                        match result {
                            Ok(relations) => self.relations = relations,
                            Err(error) => self.error = Some(error),
                        }
                    }
                }
                Event::Imported(results) => {
                    self.busy = None;
                    let mut added = Vec::new();
                    for result in results {
                        match result.and_then(|e| {
                            let id = e.id.clone();
                            self.case.as_mut().unwrap().add_evidence(e)?;
                            Ok(id)
                        }) {
                            Ok(id) => {
                                self.selected_evidence = Some(id.clone());
                                added.push(id);
                            }
                            Err(e) => self.error = Some(e),
                        }
                    }
                    if !added.is_empty() {
                        self.artifact_choices.clear();
                        self.query_epoch.fetch_add(1, Ordering::Relaxed);
                        self.selection_epoch += 1;
                        self.selected = None;
                        self.reset_hex();
                        self.selected_run = None;
                        self.selected_row = None;
                        self.scope.clear();
                        self.index = ResultIndex::default();
                        self.result_tree = ResultTree::default();
                        self.row_cache.clear();
                        self.inflight.clear();
                        self.view = View::Workspace;
                    }
                    self.message = format!("Added {} evidence file(s)", added.len());
                    if !added.is_empty() {
                        self.open_analysis_dialog(added, window, cx);
                    }
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
                    let saved = match self.case.as_mut().map(|c| c.finish(&id, &outcome)) {
                        Some(Ok(())) => true,
                        Some(Err(error)) => {
                            self.error = Some(error);
                            self.queue_paused = true;
                            false
                        }
                        None => false,
                    };
                    self.message = format!("Analysis {}", outcome.status.label().to_lowercase());
                    if outcome.status == RunStatus::Failed {
                        self.error = Some(outcome.message.chars().take(1500).collect());
                    }
                    if let Some(request) = self.file_dumps.remove(&id) {
                        if saved && outcome.status == RunStatus::Completed {
                            self.finish_file_dump(&id, request.executable);
                            if self.selection_epoch == request.selection_epoch
                                && self
                                    .selected
                                    .as_ref()
                                    .is_some_and(|r| r.id == request.record_id)
                            {
                                if !request.show_hex {
                                    self.detail = DetailTab::Files;
                                }
                                if self.hex_visible {
                                    self.load_hex(cx);
                                }
                            }
                        }
                    } else if self.scope.is_empty() || self.scope.contains(&id) {
                        self.select_run(id, window, cx);
                    } else if self.result_group() == Some(ArtifactGroup::Processes)
                        && self.case.as_ref().is_some_and(|case| {
                            case.document.runs.iter().any(|run| {
                                run.id == id
                                    && Some(&run.evidence_id) == self.selected_evidence.as_ref()
                                    && matches!(
                                        run.plugin.as_str(),
                                        "windows.handles.Handles"
                                            | "linux.lsof.Lsof"
                                            | "mac.lsof.Lsof"
                                    )
                            })
                        })
                    {
                        self.start_query(cx);
                    }
                }
                Event::Indexed(epoch, result) => {
                    if epoch != self.query_epoch.load(Ordering::Relaxed) {
                        continue;
                    }
                    self.loading = false;
                    match result {
                        Ok((index, rows, tree)) => {
                            self.index = index;
                            self.result_tree = tree;
                            self.tree_cursor = None;
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
                            } else if self.selected.as_ref().is_some_and(|r| {
                                !self.result_tree.visible.iter().any(|(i, _)| {
                                    self.result_tree.nodes[*i].record_id == Some(r.id)
                                }) && !self.index.ids.contains(&r.id)
                            }) {
                                self.selected = None;
                                self.selected_row = None;
                                self.reset_hex();
                            }
                            if let Some((position, (node, _))) = self
                                .result_tree
                                .visible
                                .iter()
                                .enumerate()
                                .find(|(_, (i, _))| {
                                    self.selected.as_ref().is_some_and(|record| {
                                        self.result_tree.nodes[*i].record_id == Some(record.id)
                                    })
                                })
                            {
                                self.tree_cursor = Some(*node);
                                self.result_scroll
                                    .scroll_to_item(position, ScrollStrategy::Nearest);
                            }
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Event::ColumnFitted(query_epoch, fit_epoch, column, result) => {
                    if query_epoch != self.query_epoch.load(Ordering::Relaxed)
                        || fit_epoch != self.column_fit_epoch.load(Ordering::Relaxed)
                    {
                        continue;
                    }
                    match result {
                        Ok(width) => {
                            self.column_widths.insert(column, width);
                        }
                        Err(error) => self.error = Some(error),
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
                            if let Some(evidence) = self
                                .case
                                .as_ref()
                                .and_then(|case| {
                                    case.document.runs.iter().find(|run| run.id == r.run_id)
                                })
                                .map(|run| run.evidence_id.clone())
                                && self.selected_evidence.as_ref() != Some(&evidence)
                            {
                                self.selected_evidence = Some(evidence);
                                self.artifact_choices.clear();
                                self.sync_os();
                            }
                            self.view = View::Workspace;
                            if !self.scope.contains(&r.run_id)
                                && !self
                                    .result_tree
                                    .nodes
                                    .iter()
                                    .any(|node| node.record_id == Some(r.id))
                            {
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
                Event::Help(plugin, result) => {
                    self.busy = None;
                    match result {
                        Ok(s) if self.plugin.as_ref() == Some(&plugin) => self.plugin_help = s,
                        Ok(_) => {}
                        Err(e) => self.analysis_error = Some(e),
                    }
                }
                Event::Exported(result) => match result {
                    Ok(p) => self.message = format!("Exported {}", p.display()),
                    Err(e) => self.error = Some(format!("Export failed: {e}")),
                },
                Event::HexLoaded(epoch, result) => {
                    if epoch != self.hex_epoch {
                        continue;
                    }
                    self.hex_view = match result {
                        Ok((files, page)) => {
                            self.hex_offset.update(cx, |input, cx| {
                                input.set_value(format!("{:#x}", page.offset), window, cx)
                            });
                            HexView::Ready { files, page }
                        }
                        Err(error) => HexView::Error(error),
                    };
                }
            }
        }
        if self.query_due.is_some_and(|t| Instant::now() >= t) {
            self.query_due = None;
            self.start_query(cx);
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
