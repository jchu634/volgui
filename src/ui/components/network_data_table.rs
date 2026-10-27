// Virtualized network occurrences, sharing the graph's cached filter projection.
use super::*;
use volgui::network::Entry;

const COLUMNS: &[(&str, f32)] = &[
    ("Finding", 240.),
    ("Local IP", 170.),
    ("Local port", 85.),
    ("Remote IP", 170.),
    ("Remote port", 95.),
    ("Protocol", 90.),
    ("State", 130.),
    ("PID", 85.),
    ("Process", 160.),
    ("Created", 190.),
    ("Source run", 270.),
    ("Source row", 95.),
];

pub(in crate::ui) struct NetworkTable {
    workspace: WeakEntity<Workspace>,
    indices: Arc<Vec<usize>>,
    order: Vec<usize>,
    sort: Option<(usize, ColumnSort)>,
    synced_selection: Option<(i64, usize)>,
    pointer_scroll: Option<Point<Pixels>>,
}

impl NetworkTable {
    pub(in crate::ui) fn new(workspace: WeakEntity<Workspace>) -> Self {
        Self {
            workspace,
            indices: Arc::default(),
            order: Vec::new(),
            sort: None,
            synced_selection: None,
            pointer_scroll: None,
        }
    }

    fn value(entry: &Entry, col: usize) -> String {
        match col {
            0 => entry.source.record.text("Finding"),
            1 => entry
                .local
                .as_ref()
                .map(|e| e.address.clone())
                .unwrap_or_default(),
            2 => entry
                .local
                .as_ref()
                .and_then(|e| e.port)
                .map(|p| p.to_string())
                .unwrap_or_default(),
            3 => entry
                .remote
                .as_ref()
                .map(|e| e.address.clone())
                .unwrap_or_default(),
            4 => entry
                .remote
                .as_ref()
                .and_then(|e| e.port)
                .map(|p| p.to_string())
                .unwrap_or_default(),
            5 => entry.protocol.clone(),
            6 => entry.state.clone(),
            7 => entry.pid.clone(),
            8 => entry.owner.clone(),
            9 => entry.created.clone(),
            10 => entry.source.run_id.clone(),
            11 => entry.source.row.to_string(),
            _ => String::new(),
        }
    }

    fn sort_rows(&mut self, entries: &[Entry]) {
        self.order = self.indices.as_ref().clone();
        if let Some((col, sort)) = self.sort {
            let mut keys: Vec<_> = self
                .order
                .iter()
                .map(|i| {
                    let text = Self::value(&entries[*i], col).to_ascii_lowercase();
                    let number = if matches!(col, 2 | 4 | 7 | 11) {
                        text.parse::<u64>().ok()
                    } else {
                        None
                    };
                    (*i, number, text)
                })
                .collect();
            keys.sort_by(|a, b| {
                let cmp = a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2));
                if sort == ColumnSort::Descending {
                    cmp.reverse()
                } else {
                    cmp
                }
            });
            self.order = keys.into_iter().map(|(i, _, _)| i).collect();
        }
    }

    pub(in crate::ui) fn record_id(&self, row: usize, entries: &[Entry]) -> Option<i64> {
        self.order
            .get(row)
            .and_then(|i| entries.get(*i))
            .map(|entry| entry.source.id)
    }
}

impl TableDelegate for NetworkTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }
    fn rows_count(&self, _: &App) -> usize {
        self.order.len()
    }
    fn column(&self, col: usize, _: &App) -> DataColumn {
        let (label, width) = COLUMNS[col];
        DataColumn::new(format!("network-{col}"), label)
            .width(px(width))
            .movable(false)
            .sort(
                self.sort
                    .filter(|(i, _)| *i == col)
                    .map_or(ColumnSort::Default, |(_, sort)| sort),
            )
    }
    fn perform_sort(
        &mut self,
        col: usize,
        sort: ColumnSort,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        self.sort = (sort != ColumnSort::Default).then_some((col, sort));
        if let Some(workspace) = self.workspace.upgrade() {
            self.sort_rows(&workspace.read(cx).network.entries);
        }
        self.synced_selection = None;
        let workspace = self.workspace.clone();
        cx.defer(move |cx| {
            let _ = workspace.update(cx, |_, cx| cx.notify());
        });
        cx.notify();
    }
    fn render_td(
        &mut self,
        row: usize,
        col: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div()
            .text_xs()
            .whitespace_nowrap()
            .overflow_hidden()
            .child(SelectableText::new(
                ("network-table-cell", row * COLUMNS.len() + col),
                self.cell_text(row, col, cx),
            ))
    }
    fn render_tr(
        &mut self,
        row: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let partial = self.workspace.upgrade().is_some_and(|workspace| {
            self.order
                .get(row)
                .and_then(|i| workspace.read(cx).network.entries.get(*i))
                .is_some_and(|entry| entry.source.record.is_partial_match())
        });
        div()
            .id(("network-table-row", row))
            .when(partial, |row| {
                partial_matches::highlight_row(row).aria_label("Partial match")
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|state, _, _, _| {
                    let offset = state.vertical_scroll_handle.0.borrow().base_handle.offset();
                    state.delegate_mut().pointer_scroll = Some(offset);
                }),
            )
            .on_click(cx.listener(|state, event, window, cx| {
                let offset = state.delegate_mut().pointer_scroll.take();
                // Match the result browser's handling of selectable text inside DataTable.
                if matches!(event, ClickEvent::Mouse(_)) {
                    gpui_kit::base::TextSelection::end(window, cx);
                }
                if let (ClickEvent::Mouse(event), Some(offset)) = (event, offset)
                    && (event.up.position - event.down.position).magnitude() < 4.
                {
                    let scroll = state.vertical_scroll_handle.clone();
                    cx.defer(move |_| {
                        let mut scroll = scroll.0.borrow_mut();
                        scroll.deferred_scroll_to_item = None;
                        scroll.base_handle.set_offset(offset);
                    });
                }
            }))
    }
    fn cell_text(&self, row: usize, col: usize, cx: &App) -> String {
        let Some(workspace) = self.workspace.upgrade() else {
            return String::new();
        };
        let workspace = workspace.read(cx);
        self.order
            .get(row)
            .and_then(|i| workspace.network.entries.get(*i))
            .map(|entry| Self::value(entry, col))
            .unwrap_or_default()
    }
    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div().p_4().text_sm().text_color(cx.theme().muted_foreground).child("No network entries match these filters. Clear the search or turn off the noise filters to see more entries.")
    }
}

impl Workspace {
    pub(in crate::ui) fn sync_network_table(
        &self,
        indices: Arc<Vec<usize>>,
        cx: &mut Context<Self>,
    ) {
        self.network_table.update(cx, |state, cx| {
            let changed = !Arc::ptr_eq(&state.delegate().indices, &indices);
            if changed {
                let delegate = state.delegate_mut();
                delegate.indices = indices;
                delegate.sort_rows(&self.network.entries);
                delegate.synced_selection = None;
                state.refresh(cx);
                state.scroll_to_row(0, cx);
            }
            let selected = self.selected.as_ref().and_then(|record| {
                state
                    .delegate()
                    .order
                    .iter()
                    .position(|i| self.network.entries[*i].source.id == record.id)
                    .map(|row| (record.id, row))
            });
            if state.delegate().synced_selection != selected {
                state.delegate_mut().synced_selection = selected;
                if let Some((_, row)) = selected {
                    state.set_selected_row(row, cx);
                } else {
                    state.clear_selection(cx);
                }
            }
            cx.notify();
        });
    }
}
