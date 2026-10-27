// Scroll positions belong to this workspace session, never to settings or case files.
use super::*;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) enum ScrollArea {
    Analyses,
    Bookmarks,
    CaseInfo,
    NewCase,
    Evidence,
    PluginHelp(Option<String>),
    NetworkNavigation(Option<String>),
    Details(Option<i64>, DetailTab),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ResultScope {
    evidence: Option<String>,
    group: Option<ArtifactGroup>,
    runs: Vec<String>,
}

impl ResultScope {
    fn new(evidence: Option<String>, group: Option<ArtifactGroup>, mut runs: Vec<String>) -> Self {
        runs.sort_unstable();
        Self {
            evidence,
            group,
            runs,
        }
    }
}

#[derive(Clone, Default)]
struct TablePosition {
    vertical: Point<Pixels>,
    horizontal: Point<Pixels>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResultTableKind {
    Results,
    Tree,
    Network,
}

impl TablePosition {
    fn capture<D: TableDelegate>(table: &TableState<D>) -> Self {
        Self {
            vertical: table.vertical_scroll_handle.0.borrow().base_handle.offset(),
            horizontal: table.horizontal_scroll_handle.offset(),
        }
    }

    fn restore<D: TableDelegate>(&self, table: &mut TableState<D>) {
        restore_list(&table.vertical_scroll_handle, self.vertical);
        // Discard any column scroll queued before the table had a layout.
        table.horizontal_scroll_handle = ScrollHandle::new().into();
        table.horizontal_scroll_handle.set_offset(self.horizontal);
    }
}

fn restore_list(handle: &UniformListScrollHandle, offset: Point<Pixels>) {
    let mut state = handle.0.borrow_mut();
    state.deferred_scroll_to_item = None;
    state.base_handle.set_offset(offset);
}

#[derive(Clone, Default)]
pub(super) struct ResultPosition {
    files: Point<Pixels>,
    results: TablePosition,
    tree: TablePosition,
    network_table: TablePosition,
    network: Point<Pixels>,
    network_sidebar: Point<Pixels>,
}

#[derive(Default)]
pub(super) struct SessionScroll {
    areas: RefCell<HashMap<ScrollArea, ScrollHandle>>,
    results: HashMap<ResultScope, ResultPosition>,
    active: Option<ResultScope>,
    pending: Option<ResultPosition>,
    pending_tables: RefCell<HashMap<ResultTableKind, TablePosition>>,
}

impl SessionScroll {
    pub(super) fn area(&self, area: ScrollArea) -> ScrollHandle {
        self.areas.borrow_mut().entry(area).or_default().clone()
    }

    pub(super) fn page(&self, area: ScrollArea, content: Div) -> AnyElement {
        let scroll = self.area(area);
        div()
            .id("session-page")
            .flex_1()
            .min_h_0()
            .min_w_0()
            .relative()
            .overflow_hidden()
            .child(
                div()
                    .id("session-page-area")
                    .size_full()
                    .flex()
                    .flex_col()
                    .overflow_y_scroll()
                    .track_scroll(&scroll)
                    .child(content.flex_none().min_h_full().w_full()),
            )
            .child(
                div()
                    .absolute()
                    .inset_0()
                    .child(Scrollbar::vertical(&scroll).viewport_from_layout()),
            )
            .into_any_element()
    }
}

impl Workspace {
    pub(super) fn result_position(&self, cx: &App) -> ResultPosition {
        if let Some(position) = &self.scroll_state.pending {
            return position.clone();
        }
        let pending_tables = self.scroll_state.pending_tables.borrow();
        let table_position = |kind, current| pending_tables.get(&kind).cloned().unwrap_or(current);
        ResultPosition {
            files: self.result_scroll.0.borrow().base_handle.offset(),
            results: table_position(
                ResultTableKind::Results,
                TablePosition::capture(self.result_table.read(cx)),
            ),
            tree: table_position(
                ResultTableKind::Tree,
                TablePosition::capture(self.tree_table.read(cx)),
            ),
            network_table: table_position(
                ResultTableKind::Network,
                TablePosition::capture(self.network_table.read(cx)),
            ),
            network: self.network_scroll.offset(),
            network_sidebar: self.network_sidebar_scroll.offset(),
        }
    }

    pub(super) fn remember_result_scroll(&mut self, cx: &App) {
        // Empty loading views can clamp live handles to zero. Keep the saved position
        // until the destination's data and table selection have both been applied.
        if self.loading || self.network_loading {
            return;
        }
        if let Some(scope) = self.scroll_state.active.clone() {
            let position = self.result_position(cx);
            self.scroll_state.results.insert(scope, position);
        }
    }

    pub(super) fn prepare_result_scroll(&mut self, position: Option<ResultPosition>) {
        let scope = ResultScope::new(
            self.selected_evidence.clone(),
            self.result_group(),
            self.scope.clone(),
        );
        let position = position.unwrap_or_else(|| {
            self.scroll_state
                .results
                .get(&scope)
                .cloned()
                .unwrap_or_default()
        });
        *self.scroll_state.pending_tables.borrow_mut() = HashMap::from([
            (ResultTableKind::Results, position.results.clone()),
            (ResultTableKind::Tree, position.tree.clone()),
            (ResultTableKind::Network, position.network_table.clone()),
        ]);
        self.scroll_state.pending = Some(position);
        self.scroll_state.active = Some(scope);
    }

    pub(super) fn restore_table_scroll<D: TableDelegate>(
        &self,
        kind: ResultTableKind,
        table: &Entity<TableState<D>>,
        cx: &mut Context<Self>,
    ) {
        if self.loading || self.network_loading {
            return;
        }
        if let Some(position) = self.scroll_state.pending_tables.borrow_mut().remove(&kind) {
            table.update(cx, |table, cx| {
                position.restore(table);
                cx.notify();
            });
        }
    }

    pub(super) fn restore_result_scroll(&mut self, cx: &mut Context<Self>) {
        if self.view != View::Workspace || self.loading || self.network_loading {
            return;
        }
        let Some(position) = self.scroll_state.pending.take() else {
            return;
        };
        restore_list(&self.result_scroll, position.files);
        self.network_scroll.set_offset(position.network);
        self.network_sidebar_scroll
            .set_offset(position.network_sidebar);
        cx.notify();
    }

    pub(super) fn reset_scroll_state(&mut self, cx: &mut Context<Self>) {
        self.scroll_state = SessionScroll::default();
        self.result_scroll = UniformListScrollHandle::default();
        self.queue_scroll = UniformListScrollHandle::default();
        self.relations_scroll = UniformListScrollHandle::default();
        self.network_scroll.set_offset(Point::default());
        self.network_sidebar_scroll.set_offset(Point::default());
        self.application_text_scroll.set_offset(Point::default());
        self.reset_result_table(cx);
        self.network_table.update(cx, |table, cx| {
            TablePosition::default().restore(table);
            cx.notify();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn areas_keep_independent_positions_for_the_session() {
        let session = SessionScroll::default();
        let area = ScrollArea::Details(Some(42), DetailTab::Overview);
        let offset = point(px(-75.), px(-500.));
        session.area(area.clone()).set_offset(offset);
        assert_eq!(session.area(area.clone()).offset(), offset);
        assert_eq!(
            session
                .area(ScrollArea::Details(Some(42), DetailTab::Raw))
                .offset(),
            Point::default()
        );
        assert_eq!(
            session
                .area(ScrollArea::Details(Some(43), DetailTab::Overview))
                .offset(),
            Point::default()
        );
        assert_eq!(
            SessionScroll::default().area(area).offset(),
            Point::default()
        );
    }

    #[::core::prelude::v1::test]
    fn result_scopes_ignore_run_order_and_separate_evidence_and_groups() {
        let scope = ResultScope::new(
            Some("a".into()),
            Some(ArtifactGroup::Processes),
            vec!["2".into(), "1".into()],
        );
        assert!(
            scope
                == ResultScope::new(
                    Some("a".into()),
                    Some(ArtifactGroup::Processes),
                    vec!["1".into(), "2".into()]
                )
        );
        assert!(
            scope
                != ResultScope::new(
                    Some("b".into()),
                    Some(ArtifactGroup::Processes),
                    vec!["1".into(), "2".into()]
                )
        );
        assert!(
            scope
                != ResultScope::new(
                    Some("a".into()),
                    Some(ArtifactGroup::Files),
                    vec!["1".into(), "2".into()]
                )
        );
    }

    #[::core::prelude::v1::test]
    fn restoring_a_list_cancels_queued_selection_scrolling() {
        let handle = UniformListScrollHandle::default();
        handle.scroll_to_item(0, ScrollStrategy::Top);
        let offset = point(px(-20.), px(-1234.));
        restore_list(&handle, offset);
        assert_eq!(handle.0.borrow().base_handle.offset(), offset);
        assert!(handle.0.borrow().deferred_scroll_to_item.is_none());
    }
}
