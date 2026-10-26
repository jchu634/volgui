// Tracks workspace navigation and closes cases.
use super::*;

pub(super) struct Location {
    view: View,
    evidence: Option<String>,
    scope: Vec<String>,
    scope_label: String,
    selected: Option<Arc<StoredRecord>>,
    selected_run: Option<String>,
    query: String,
    column_filters: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    sort: Option<(String, bool)>,
    browser: ArtifactGroup,
    detail: DetailTab,
    network_table_view: bool,
    network_hide_system: bool,
    network_hide_noise: bool,
    network_focus: Option<String>,
    network_endpoint: Option<volgui::network::Selection>,
    network_protocol: Option<String>,
    network_state: Option<String>,
    network_interesting: bool,
    network_all_sources: bool,
    network_sidebar_page: usize,
    network_offset: Point<Pixels>,
    content_sidebar_visible: bool,
    file_offset_physical: bool,
}

impl Workspace {
    pub(super) fn remember_location(&mut self, cx: &App) {
        let location = Location {
            view: self.view,
            evidence: self.selected_evidence.clone(),
            scope: self.scope.clone(),
            scope_label: self.scope_label.clone(),
            selected: self.selected.clone(),
            selected_run: self.selected_run.clone(),
            query: self.query.read(cx).value().to_string(),
            column_filters: self.column_filters.clone(),
            sort: self.sort.clone(),
            browser: self.browser_group,
            detail: self.detail,
            network_table_view: self.network_table_view,
            network_hide_system: self.network_hide_system,
            network_hide_noise: self.network_hide_noise,
            network_focus: self.network_focus.clone(),
            network_endpoint: self.network_endpoint.clone(),
            network_protocol: self.network_protocol.clone(),
            network_state: self.network_state.clone(),
            network_interesting: self.network_interesting,
            network_all_sources: self.network_all_sources,
            network_sidebar_page: self.network_sidebar_page,
            network_offset: self.network_scroll.offset(),
            content_sidebar_visible: self.content_sidebar_visible,
            file_offset_physical: self.file_offset_physical,
        };
        if self.back_stack.last().is_some_and(|last| {
            last.view == location.view
                && last.evidence == location.evidence
                && last.scope == location.scope
                && last.selected.as_ref().map(|r| r.id) == location.selected.as_ref().map(|r| r.id)
                && last.query == location.query
                && last.browser == location.browser
        }) {
            return;
        }
        if self.back_stack.len() == 64 {
            self.back_stack.remove(0);
        }
        self.back_stack.push(location);
    }
    pub(super) fn navigate(&mut self, view: View, cx: &mut Context<Self>) {
        if self.view == view {
            return;
        }
        self.remember_location(cx);
        self.view = view;
        cx.notify();
    }
    pub(super) fn go_back(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(location) = self.back_stack.pop() else {
            return;
        };
        self.selection_epoch += 1;
        self.relation_epoch += 1;
        self.view = location.view;
        self.selected_evidence = location.evidence;
        self.scope = location.scope;
        self.scope_label = location.scope_label;
        self.selected_run = location.selected_run;
        self.selected_row = location.selected.as_ref().map(|r| r.row);
        self.selected = location.selected.clone();
        self.sort = location.sort;
        self.column_filters = location.column_filters;
        self.browser_group = location.browser;
        self.detail = location.detail;
        self.index = ResultIndex::default();
        self.network = volgui::network::Graph::default();
        *self.network_cache.borrow_mut() = Default::default();
        self.network_table_view = location.network_table_view;
        self.network_hide_system = location.network_hide_system;
        self.network_hide_noise = location.network_hide_noise;
        self.network_focus = location.network_focus;
        self.network_endpoint = location.network_endpoint;
        self.network_protocol = location.network_protocol;
        self.network_state = location.network_state;
        self.network_interesting = location.network_interesting;
        self.network_all_sources = location.network_all_sources;
        self.network_sidebar_page = location.network_sidebar_page;
        self.network_scroll.set_offset(location.network_offset);
        self.content_sidebar_visible = location.content_sidebar_visible;
        self.file_offset_physical = location.file_offset_physical;
        self.clear_result_tree();
        self.row_cache.clear();
        self.result_scroll = UniformListScrollHandle::default();
        self.reset_result_table(cx);
        self.query
            .update(cx, |s, cx| s.set_value(location.query, window, cx));
        self.query_due = None;
        if let Some(record) = location.selected {
            self.show_record((*record).clone(), window, cx);
        }
        if self.case.is_some() {
            self.sync_os();
            self.start_query(cx);
        }
        cx.notify();
    }
    pub(super) fn close_case(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_switch() {
            return;
        }
        self.query_epoch.fetch_add(1, Ordering::Relaxed);
        self.selection_epoch += 1;
        self.relation_epoch += 1;
        self.query_due = None;
        self.case = None;
        self.network = volgui::network::Graph::default();
        *self.network_cache.borrow_mut() = Default::default();
        self.network_endpoint = None;
        self.network_focus = None;
        self.reset_file_listing();
        self.handles = None;
        self.handles_loading = false;
        self.handle_epoch += 1;
        self.view = View::Workspace;
        self.back_stack.clear();
        self.selected_evidence = None;
        self.selected_run = None;
        self.selected_row = None;
        self.selected = None;
        self.content_sidebar_visible = false;
        self.reset_hex();
        self.scope.clear();
        self.scope_label.clear();
        self.index = ResultIndex::default();
        self.clear_result_tree();
        self.tree_states.clear();
        self.row_cache.clear();
        self.inflight.clear();
        self.relations = ProcessRelations::default();
        self.analysis_drafts.clear();
        self.queue_open = false;
        self.batch_total = 0;
        self.batch_finished = 0;
        self.loading = false;
        self.message = "Case closed".into();
        self.error = None;
        cx.notify();
    }
}
