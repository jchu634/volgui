// Owns shared workspace state and dispatches background events.
mod analysis_actions;
mod case_actions;
mod chrome;
mod components;
mod exports;
mod file_actions;
mod investigation_actions;
mod navigation;
mod popups;
mod result_actions;
mod shell;
mod views;

use gpui_kit::{
    assets::IconName,
    base::{Button as ActionButton, Link as TextLink, SelectableText},
    component::{
        ActiveTheme, Disableable, Icon, Selectable, Sizable, TitleBar, WindowExt,
        button::{Button, ButtonVariants},
        checkbox::Checkbox,
        input::{Input, InputEvent, InputState},
        list::ListItem,
        menu::{DropdownMenu, PopupMenu, PopupMenuItem},
        notification::Notification,
        popover::Popover,
        progress::ProgressCircle,
        resizable::{h_resizable, resizable_panel, v_resizable},
        scroll::{ScrollableElement, Scrollbar, ScrollbarMode},
        table::{
            Column as DataColumn, ColumnSort, DataTable, TableDelegate, TableEvent, TableState,
        },
        tooltip::Tooltip,
    },
    prelude::FluentBuilder,
    *,
};
use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap, HashSet},
    ops::Range,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};
use volgui::{
    analyses::{AnalysisDraft, basic_label, chooser_plugins, queue_retries_with_engine},
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
    Handles,
    SourceBytes,
}

struct FileDumpRequest {
    record_id: i64,
    selection_epoch: u64,
    executable: Option<PathBuf>,
    show_hex: bool,
}

struct FileListing {
    target: (PathBuf, RunStatus),
    result: Option<std::result::Result<Vec<volgui::extracted_files::ExtractedFile>, String>>,
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
struct QueryResult {
    index: ResultIndex,
    rows: Vec<StoredRecord>,
    tree: ResultTree,
    file_states: HashMap<i64, volgui::analysis::files::RecoveryState>,
    recovery: Option<volgui::analysis::files::RecoveryIndex>,
}

enum Event {
    Opened(std::result::Result<Case, String>),
    Validated(std::result::Result<Installation, String>),
    Imported(Vec<std::result::Result<Evidence, String>>),
    Verified(String, std::result::Result<Evidence, String>),
    Progress(String),
    Finished(String, Outcome),
    FilesListed(
        u64,
        std::result::Result<Vec<volgui::extracted_files::ExtractedFile>, String>,
    ),
    FileActionCompleted(PathBuf, std::result::Result<String, String>),
    ImHexLocated(Option<PathBuf>),
    Indexed(u64, std::result::Result<QueryResult, String>),
    NetworkLoaded(
        u64,
        std::result::Result<Option<volgui::network::Graph>, String>,
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
    BrowserPrepared(std::result::Result<Vec<volgui::case::Run>, String>),
    HandlesLoaded(
        u64,
        std::result::Result<volgui::results::HandlePage, String>,
    ),
    DatabaseLoaded(
        u64,
        u64,
        std::result::Result<volgui::file_content::DatabasePage, String>,
    ),
}
struct Busy {
    label: String,
    cancel: Arc<AtomicBool>,
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
    network: volgui::network::Graph,
    network_table: Entity<TableState<components::network_data_table::NetworkTable>>,
    network_table_view: bool,
    network_hide_system: bool,
    network_hide_noise: bool,
    network_cache: RefCell<views::network::NetworkViewCache>,
    network_loading: bool,
    network_focus: Option<String>,
    network_endpoint: Option<volgui::network::Selection>,
    network_protocol: Option<String>,
    network_state: Option<String>,
    network_interesting: bool,
    network_all_sources: bool,
    network_sidebar_page: usize,
    network_scroll: ScrollHandle,
    network_sidebar_scroll: ScrollHandle,
    tree_cursor: Option<usize>,
    row_cache: HashMap<i64, Arc<StoredRecord>>,
    inflight: HashSet<i64>,
    column_filters: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    sort: Option<(String, bool)>,
    query_epoch: Arc<AtomicU64>,
    query_due: Option<Instant>,
    loading: bool,
    selection_epoch: u64,
    browser_group: ArtifactGroup,
    show_file_handles: bool,
    show_unavailable_files: bool,
    file_recovery_states: HashMap<i64, volgui::analysis::files::RecoveryState>,
    file_recovery: Option<volgui::analysis::files::RecoveryIndex>,
    result_scroll: UniformListScrollHandle,
    result_table: Entity<TableState<components::result_data_table::ResultTable>>,
    analysis_table: Entity<TableState<components::analysis_data_table::AnalysisTable>>,
    database_table: Entity<TableState<components::database_data_table::DatabaseTable>>,
    details_scroll: ScrollHandle,
    queue_scroll: UniformListScrollHandle,
    relations_scroll: UniformListScrollHandle,
    column_widths: HashMap<String, Pixels>,
    column_fit_epoch: Arc<AtomicU64>,
    relations: ProcessRelations,
    relation_epoch: u64,
    raw_expanded: HashSet<String>,
    raw_expand_all: bool,
    queue_open: bool,
    popup_panels: RefCell<HashMap<popups::PanelKind, Entity<popups::PopupPanel>>>,
    file_dumps: HashMap<String, FileDumpRequest>,
    file_listing: Option<FileListing>,
    file_listing_epoch: u64,
    imhex_path: Option<PathBuf>,
    file_offset_physical: bool,
    hex_view: HexView,
    hex_editor: Option<Entity<components::hex_editor::HexEditor>>,
    content_sidebar_visible: bool,
    hex_scroll: ScrollHandle,
    hex_epoch: u64,
    content_encoding: volgui::extracted_files::ContentEncoding,
    database_view: Option<std::result::Result<volgui::file_content::DatabasePage, String>>,
    database_epoch: u64,
    handles: Option<volgui::results::HandlePage>,
    handles_loading: bool,
    handle_epoch: u64,
    string_needle: Entity<InputState>,
    application_pid: Entity<InputState>,
    analysis_application_pid: Entity<InputState>,
    analysis_application_contains: Entity<InputState>,
    application_text_scroll: ScrollHandle,
    string_ignore_case: bool,
    registry_key: Entity<InputState>,
    artifact_open: Option<ArtifactGroup>,
    artifact_choices: HashMap<ArtifactGroup, BTreeSet<String>>,
    analysis_group_filter: Option<ArtifactGroup>,
    analysis_collapsed_groups: std::collections::HashSet<ArtifactGroup>,
    sidebar_visible: bool,
    busy: Option<Busy>,
    running: HashMap<String, Busy>,
    queue_paused: bool,
    browser_recovery_pending: bool,
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
    job_limit: Entity<InputState>,
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
        let analysis_application_pid = field("", "Process ID", window, cx);
        let analysis_application_contains = field("", "Optional literal text", window, cx);
        let workspace = cx.entity().downgrade();
        let result_table = cx.new(|cx| {
            TableState::new(
                components::result_data_table::ResultTable::new(workspace.clone()),
                window,
                cx,
            )
            .col_movable(false)
            .col_selectable(false)
            .row_header(false)
            .loop_selection(false)
            .select_on_modifier_click(false)
        });
        let network_table = cx.new(|cx| {
            TableState::new(
                components::network_data_table::NetworkTable::new(workspace.clone()),
                window,
                cx,
            )
            .col_movable(false)
            .col_selectable(false)
            .row_header(false)
            .loop_selection(false)
            .select_on_modifier_click(false)
        });
        let analysis_table = cx.new(|cx| {
            TableState::new(
                components::analysis_data_table::AnalysisTable::new(workspace.clone()),
                window,
                cx,
            )
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
            .row_header(false)
        });
        let database_table = cx.new(|cx| {
            TableState::new(
                components::database_data_table::DatabaseTable::new(workspace),
                window,
                cx,
            )
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
            .row_header(false)
        });
        let subscriptions = vec![
            cx.subscribe(&network_table, |this, table, event: &TableEvent, cx| {
                if let TableEvent::SelectRow(row) = event
                    && let Some(id) = table
                        .read(cx)
                        .delegate()
                        .record_id(*row, &this.network.entries)
                    && this.selected.as_ref().is_none_or(|record| record.id != id)
                {
                    this.detail = DetailTab::Overview;
                    this.load_record(id, cx);
                }
            }),
            cx.subscribe(
                &result_table,
                |this, _, event: &TableEvent, cx| match event {
                    TableEvent::SelectRow(row) => {
                        if let Some(id) = this.index.ids.get(*row).copied()
                            && this.selected.as_ref().is_none_or(|record| record.id != id)
                        {
                            this.load_record(id, cx);
                        }
                    }
                    TableEvent::ColumnWidthsChanged(widths) => {
                        this.column_fit_epoch.fetch_add(1, Ordering::Relaxed);
                        for (column, width) in this.result_columns().iter().zip(widths) {
                            this.column_widths.insert(column.key.clone(), *width);
                        }
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe(&query, |this, _, e: &InputEvent, cx| {
                if matches!(e, InputEvent::Change) {
                    if this.result_group() == Some(ArtifactGroup::Network) {
                        this.network_scroll.set_offset(Point::default());
                        this.network_sidebar_page = 0;
                    }
                    this.query_due = Some(Instant::now() + Duration::from_millis(180));
                    cx.notify();
                }
            }),
            cx.subscribe(&plugin_query, |_, _, _: &InputEvent, cx| cx.notify()),
            cx.subscribe(
                &analysis_application_pid,
                |this, _, event: &InputEvent, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.save_application_options(cx);
                    }
                },
            ),
            cx.subscribe(
                &analysis_application_contains,
                |this, _, event: &InputEvent, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.save_application_options(cx);
                    }
                },
            ),
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
                "Path to vol.exe, vol-rs.exe or its installation directory",
                window,
                cx,
            ),
            symbol_path: field(
                settings.symbols.display().to_string(),
                "Optional symbols directory",
                window,
                cx,
            ),
            job_limit: field(settings.max_concurrent_jobs.to_string(), "2", window, cx),
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
            network: volgui::network::Graph::default(),
            network_table,
            network_table_view: false,
            network_hide_system: true,
            network_hide_noise: true,
            network_cache: RefCell::default(),
            network_loading: false,
            network_focus: None,
            network_endpoint: None,
            network_protocol: None,
            network_state: None,
            network_interesting: false,
            network_all_sources: false,
            network_sidebar_page: 0,
            network_scroll: ScrollHandle::default(),
            network_sidebar_scroll: ScrollHandle::default(),
            tree_cursor: None,
            row_cache: HashMap::new(),
            inflight: HashSet::new(),
            column_filters: Default::default(),
            sort: None,
            query_epoch: Arc::new(AtomicU64::new(0)),
            query_due: None,
            loading: false,
            selection_epoch: 0,
            browser_group: ArtifactGroup::Processes,
            show_file_handles: true,
            show_unavailable_files: true,
            file_recovery_states: HashMap::new(),
            file_recovery: None,
            result_scroll: UniformListScrollHandle::default(),
            result_table,
            analysis_table,
            database_table,
            details_scroll: ScrollHandle::default(),
            queue_scroll: UniformListScrollHandle::default(),
            relations_scroll: UniformListScrollHandle::default(),
            column_widths: HashMap::new(),
            column_fit_epoch: Arc::new(AtomicU64::new(0)),
            relations: ProcessRelations::default(),
            relation_epoch: 0,
            raw_expanded: HashSet::new(),
            raw_expand_all: false,
            queue_open: false,
            popup_panels: RefCell::new(HashMap::new()),
            file_dumps: HashMap::new(),
            file_listing: None,
            file_listing_epoch: 0,
            imhex_path: None,
            file_offset_physical: false,
            hex_view: HexView::Idle,
            hex_editor: None,
            content_sidebar_visible: false,
            hex_scroll: ScrollHandle::default(),
            hex_epoch: 0,
            content_encoding: volgui::extracted_files::ContentEncoding::Hex,
            database_view: None,
            database_epoch: 0,
            handles: None,
            handles_loading: false,
            handle_epoch: 0,
            string_needle: field("", "Literal string in evidence...", window, cx),
            application_pid: field("", "PID to scan", window, cx),
            analysis_application_pid,
            analysis_application_contains,
            application_text_scroll: ScrollHandle::default(),
            string_ignore_case: false,
            registry_key: field(
                "",
                "Relative registry key, e.g. Software\\Microsoft",
                window,
                cx,
            ),
            artifact_open: None,
            artifact_choices: HashMap::new(),
            analysis_group_filter: None,
            analysis_collapsed_groups: std::collections::HashSet::new(),
            sidebar_visible: true,
            busy: None,
            running: HashMap::new(),
            queue_paused: false,
            browser_recovery_pending: false,
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
            case_directory: field("", "Folder to create the case in", window, cx),
            _subscriptions: subscriptions,
        };
        this.locate_imhex();
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
            for job in this.running.values() {
                job.cancel.store(true, Ordering::Relaxed);
            }
            async {}
        })
        .detach();
        this
    }
    fn is_working(&self) -> bool {
        self.busy.is_some() || !self.running.is_empty()
    }
    fn can_switch(&self) -> bool {
        !self.is_working()
            && !self.has_queued()
            && !self.case.as_ref().is_some_and(Case::has_unsaved_changes)
    }
    fn has_queued(&self) -> bool {
        self.case.as_ref().is_some_and(|c| {
            c.document
                .runs
                .iter()
                .any(|r| r.status == RunStatus::Queued)
        })
    }
    fn start(&mut self, label: &str) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        self.busy = Some(Busy {
            label: label.into(),
            cancel: cancel.clone(),
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
        self.browser_recovery_pending = false;
        if let Some(b) = self.running.get(&id) {
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
        if let Some(case) = &mut self.case {
            while let Some(result) = case.poll_save() {
                changed = true;
                if let Err(error) = result {
                    self.error = Some(format!("Could not save case: {error}"));
                    self.queue_paused = true;
                }
            }
        }
        while let Ok(event) = self.rx.try_recv() {
            changed = true;
            match event {
                Event::FilesListed(epoch, result) => {
                    if epoch == self.file_listing_epoch
                        && self.detail == DetailTab::Files
                        && self.file_listing_target().as_ref()
                            == self.file_listing.as_ref().map(|listing| &listing.target)
                        && let Some(listing) = &mut self.file_listing
                    {
                        listing.result = Some(result);
                    }
                }
                Event::FileActionCompleted(directory, result) => {
                    if self
                        .case
                        .as_ref()
                        .is_some_and(|case| case.directory == directory)
                    {
                        match result {
                            Ok(message) => self.message = message,
                            Err(error) => self.error = Some(error),
                        }
                    }
                }
                Event::ImHexLocated(path) => self.imhex_path = path,
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
                        Ok(mut engine) => {
                            engine.settings.max_concurrent_jobs = self.settings.max_concurrent_jobs;
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
                Event::BrowserPrepared(result) => {
                    self.busy = None;
                    match result {
                        Ok(runs) => {
                            let id = runs.last().map(|r| r.id.clone());
                            self.queue_investigation(runs, window, cx);
                            if let Some(id) = id {
                                self.select_run(id, window, cx);
                            }
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                Event::HandlesLoaded(epoch, result) => {
                    if epoch == self.handle_epoch {
                        self.handles_loading = false;
                        match result {
                            Ok(page) => self.handles = Some(page),
                            Err(error) => self.error = Some(error),
                        }
                    }
                }
                Event::DatabaseLoaded(hex_epoch, epoch, result) => {
                    if hex_epoch == self.hex_epoch && epoch == self.database_epoch {
                        self.database_view = Some(result);
                    }
                }
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
                    self.running.remove(&id);
                    self.batch_finished += 1;
                    let saved = match self.case.as_mut().map(|c| c.finish_recorded(&id, &outcome)) {
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
                    if self.detail == DetailTab::Handles {
                        self.load_handles(0, cx);
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
                                if self.content_sidebar_visible {
                                    self.load_hex(cx);
                                }
                            }
                        }
                    } else if self.result_group() == Some(ArtifactGroup::Network)
                        && self.scope_label == ArtifactGroup::Network.label()
                        && self.case.as_ref().is_some_and(|case| {
                            case.document.runs.iter().any(|run| {
                                run.id == id
                                    && Some(&run.evidence_id) == self.selected_evidence.as_ref()
                                    && ArtifactGroup::for_plugin(&run.plugin)
                                        == ArtifactGroup::Network
                            })
                        })
                    {
                        self.scope = self.group_runs(ArtifactGroup::Network);
                        self.start_query(cx);
                    } else if self.scope.contains(&id) {
                        self.start_query(cx);
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
                    if matches!(
                        self.result_group(),
                        Some(ArtifactGroup::Files | ArtifactGroup::Processes)
                    ) && self.case.as_ref().is_some_and(|case| {
                        case.document.runs.iter().any(|run| {
                            run.id == id && run.plugin == volgui::extracted_files::DUMP_FILES
                        })
                    }) {
                        self.tree_cursor = None;
                        self.start_query(cx);
                    }
                }
                Event::NetworkLoaded(epoch, result) => {
                    if epoch != self.query_epoch.load(Ordering::Relaxed) {
                        continue;
                    }
                    self.network_loading = false;
                    match result {
                        Ok(Some(graph)) => {
                            self.network = graph;
                            *self.network_cache.borrow_mut() = Default::default();
                            if self
                                .network_focus
                                .as_ref()
                                .is_none_or(|ip| !self.network.addresses.contains_key(ip))
                            {
                                let mut counts = std::collections::BTreeMap::<String, usize>::new();
                                for entry in &self.network.entries {
                                    if let Some(endpoint) = &entry.local {
                                        *counts.entry(endpoint.address.clone()).or_default() += 1;
                                    }
                                }
                                self.network_focus = counts
                                    .iter()
                                    .filter(|(ip, _)| {
                                        !matches!(ip.as_str(), "0.0.0.0" | "::" | "*")
                                            && !ip
                                                .parse::<std::net::IpAddr>()
                                                .is_ok_and(|ip| ip.is_loopback())
                                    })
                                    .max_by_key(|(_, n)| *n)
                                    .or_else(|| counts.iter().max_by_key(|(_, n)| *n))
                                    .map(|(ip, _)| ip.clone())
                                    .or_else(|| self.network.addresses.keys().next().cloned());
                            }
                            if self.network_endpoint.as_ref().is_some_and(|selection| {
                                !self.network.contains_selection(selection)
                            }) {
                                self.network_endpoint = None;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => self.error = Some(error),
                    }
                }
                Event::Indexed(epoch, result) => {
                    if epoch != self.query_epoch.load(Ordering::Relaxed) {
                        continue;
                    }
                    self.loading = false;
                    match result {
                        Ok(QueryResult {
                            index,
                            rows,
                            tree,
                            file_states,
                            recovery,
                        }) => {
                            self.file_recovery_states = file_states;
                            self.file_recovery = recovery;
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
                                if self.result_group() == Some(ArtifactGroup::Applications) {
                                    if let Some(row) = self
                                        .index
                                        .ids
                                        .first()
                                        .and_then(|id| self.row_cache.get(id))
                                        .cloned()
                                    {
                                        self.show_record((*row).clone(), window, cx);
                                    }
                                } else {
                                    self.reset_hex();
                                }
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
                                self.file_offset_physical = false;
                                self.artifact_choices.clear();
                                self.sync_os();
                            }
                            self.view = View::Workspace;
                            if !self.scope.contains(&r.run_id)
                                && !(self.result_group() == Some(ArtifactGroup::Network)
                                    && self
                                        .network
                                        .entries
                                        .iter()
                                        .any(|entry| entry.source.id == r.id))
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
                    let failed_read = result.is_err();
                    self.hex_view = match result {
                        Ok((files, page)) => {
                            let offset = if self.result_group() == Some(ArtifactGroup::Applications)
                            {
                                self.selected
                                    .as_ref()
                                    .and_then(|row| row.record.fields.get("Dump offset")?.as_u64())
                                    .unwrap_or(page.offset)
                            } else {
                                page.offset
                            };
                            let editor = cx.new(|cx| {
                                components::hex_editor::HexEditor::new(
                                    page.path.clone(),
                                    page.total,
                                    offset,
                                    window,
                                    cx,
                                )
                            });
                            cx.subscribe(
                                &editor,
                                |_, _, _: &components::hex_editor::SelectionChanged, cx| {
                                    cx.notify()
                                },
                            )
                            .detach();
                            self.hex_editor = Some(editor);
                            self.hex_offset.update(cx, |input, cx| {
                                input.set_value(format!("{:#x}", page.offset), window, cx)
                            });
                            HexView::Ready { files, page }
                        }
                        Err(error) => HexView::Error(error),
                    };
                    if failed_read
                        && matches!(
                            self.result_group(),
                            Some(ArtifactGroup::Files | ArtifactGroup::Processes)
                        )
                    {
                        self.start_query(cx);
                    }
                    if self.content_encoding == volgui::extracted_files::ContentEncoding::Sqlite {
                        self.set_content_encoding(self.content_encoding, cx);
                    }
                }
            }
        }
        self.refresh_file_listing(cx);
        if self.query_due.is_some_and(|t| Instant::now() >= t) {
            self.query_due = None;
            self.start_query(cx);
            changed = true;
        }
        if self.busy.is_none() {
            self.start_next(window, cx);
        }
        for b in self.busy.iter_mut().chain(self.running.values_mut()) {
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
