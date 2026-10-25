// Adapts the workspace's indexed results to GPUI's virtualized data table.
use super::*;

pub(in crate::ui) struct ResultTable {
    workspace: WeakEntity<Workspace>,
    columns: Vec<table::Column>,
    layout: Vec<DataColumn>,
    // Last workspace selection applied to the table, including its position after sorting.
    synced_selection: Option<(i64, usize)>,
    pointer_scroll: Option<Point<Pixels>>,
}

impl ResultTable {
    pub(in crate::ui) fn new(workspace: WeakEntity<Workspace>) -> Self {
        Self {
            workspace,
            columns: Vec::new(),
            layout: Vec::new(),
            synced_selection: None,
            pointer_scroll: None,
        }
    }
}

impl TableDelegate for ResultTable {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, cx: &App) -> usize {
        self.workspace
            .upgrade()
            .map_or(0, |workspace| workspace.read(cx).index.ids.len())
    }

    fn column(&self, col: usize, _: &App) -> DataColumn {
        self.layout[col].clone()
    }

    fn perform_sort(
        &mut self,
        col: usize,
        sort: ColumnSort,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let key = self.columns[col].key.clone();
        let workspace = self.workspace.clone();
        cx.defer(move |cx| {
            let _ = workspace.update(cx, |workspace, cx| {
                workspace.sort = match sort {
                    ColumnSort::Default => None,
                    ColumnSort::Ascending => Some((key, false)),
                    ColumnSort::Descending => Some((key, true)),
                };
                workspace.start_query(cx);
            });
        });
    }

    fn fit_column(
        &mut self,
        col: usize,
        window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> Option<Pixels> {
        let column = self.columns[col].clone();
        let workspace = self.workspace.clone();
        window.defer(cx, move |window, cx| {
            let _ = workspace.update(cx, |workspace, cx| workspace.fit_column(column, window, cx));
        });
        // Measuring all indexed records remains a cancellable background job.
        None
    }

    fn visible_rows_changed(
        &mut self,
        range: Range<usize>,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let workspace = self.workspace.clone();
        cx.defer(move |cx| {
            let _ = workspace.update(cx, |workspace, _| workspace.request_rows(range));
        });
    }

    fn render_tr(
        &mut self,
        row: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let record = self.workspace.upgrade().and_then(|workspace| {
            let workspace = workspace.read(cx);
            workspace
                .index
                .ids
                .get(row)
                .and_then(|id| workspace.row_cache.get(id))
                .cloned()
        });
        if record.is_none() {
            // Refill the viewport after cache eviction, even without a range change.
            let table = cx.entity().downgrade();
            let workspace = self.workspace.clone();
            cx.defer(move |cx| {
                if let Some(table) = table.upgrade() {
                    let range = table.read(cx).visible_range().rows().clone();
                    let _ = workspace.update(cx, |workspace, _| workspace.request_rows(range));
                }
            });
        }
        div()
            .id(("result-row", row))
            .aria_label(
                record
                    .map(|record| record.record.title())
                    .unwrap_or_else(|| "Loading artifact".into()),
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|state, _, _, _| {
                    let offset = state.vertical_scroll_handle.0.borrow().base_handle.offset();
                    state.delegate_mut().pointer_scroll = Some(offset);
                }),
            )
            .on_click(cx.listener(|state, event, window, cx| {
                let offset = state.delegate_mut().pointer_scroll.take();
                // DataTable stops mouse-up propagation before the window's selection
                // layer can end the gesture. An unfinished text selection auto-scrolls
                // on later pointer movement, even after the mouse button is released.
                if matches!(event, ClickEvent::Mouse(_)) {
                    gpui_kit::base::TextSelection::end(window, cx);
                }
                if let (ClickEvent::Mouse(event), Some(offset)) = (event, offset)
                    && (event.up.position - event.down.position).magnitude() < 4.
                {
                    let scroll = state.vertical_scroll_handle.clone();
                    // DataTable adds its own selection handler after this one. Restore the
                    // pointer's viewport once that handler has queued its scroll request.
                    cx.defer(move |_| {
                        let mut scroll = scroll.0.borrow_mut();
                        scroll.deferred_scroll_to_item = None;
                        scroll.base_handle.set_offset(offset);
                    });
                }
            }))
    }

    fn render_td(
        &mut self,
        row: usize,
        col: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(workspace) = self.workspace.upgrade() else {
            return div().into_any_element();
        };
        let state = workspace.read(cx);
        let Some(id) = state.index.ids.get(row).copied() else {
            return div().into_any_element();
        };
        let column = &self.columns[col];
        let value = state
            .row_cache
            .get(&id)
            .map(|record| column.text(&record.record));
        let parent = (column.key.eq_ignore_ascii_case("ppid")
            || (state.result_group() == Some(ArtifactGroup::Web) && column.key == "PID"))
            && value
                .as_ref()
                .is_some_and(|value| !value.is_empty() && value != "0")
            && !state.group_runs(ArtifactGroup::Processes).is_empty();
        let value = value.unwrap_or_else(|| "...".into());
        let cell = div().text_xs().whitespace_nowrap().overflow_hidden();
        if parent {
            cell.child(
                record_link(
                    key("parent-cell", &format!("{id}-{}", column.key)),
                    value.clone(),
                    cx,
                )
                .on_activate(move |_, _, cx| {
                    cx.stop_propagation();
                    workspace.update(cx, |workspace, cx| {
                        workspace.open_process(value.clone(), cx)
                    });
                }),
            )
            .into_any_element()
        } else {
            cell.child(SelectableText::new(
                key("result-text", &format!("{id}-{}", column.key)),
                value,
            ))
            .into_any_element()
        }
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let message = self
            .workspace
            .upgrade()
            .map(|workspace| workspace.read(cx).results_empty_message(cx))
            .unwrap_or_default();
        div()
            .p_4()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child(message)
    }

    fn cell_text(&self, row: usize, col: usize, cx: &App) -> String {
        let Some(workspace) = self.workspace.upgrade() else {
            return String::new();
        };
        let state = workspace.read(cx);
        state
            .index
            .ids
            .get(row)
            .and_then(|id| state.row_cache.get(id))
            .map(|record| self.columns[col].text(&record.record))
            .unwrap_or_default()
    }
}

impl Workspace {
    pub(in crate::ui) fn sync_result_table(&self, cx: &mut Context<Self>) {
        let columns = self.result_columns();
        let layout: Vec<_> = columns
            .iter()
            .map(|column| {
                let sort = self
                    .sort
                    .as_ref()
                    .filter(|(key, _)| key == &column.key)
                    .map_or(ColumnSort::Default, |(_, descending)| {
                        if *descending {
                            ColumnSort::Descending
                        } else {
                            ColumnSort::Ascending
                        }
                    });
                DataColumn::new(column.key.clone(), column.label.clone())
                    .min_width(px(72.))
                    .max_width(px(1400.))
                    .width(self.column_width(column))
                    .movable(false)
                    .sort(sort)
            })
            .collect();
        let selected = self.selected.as_ref().and_then(|record| {
            self.index
                .ids
                .iter()
                .position(|id| *id == record.id)
                .map(|row| (record.id, row))
        });
        self.result_table.update(cx, |state, cx| {
            let changed = state.delegate().layout.len() != layout.len()
                || state.delegate().layout.iter().zip(&layout).any(|(a, b)| {
                    a.key != b.key || a.name != b.name || a.width != b.width || a.sort != b.sort
                });
            state.delegate_mut().columns = columns;
            if changed {
                state.delegate_mut().layout = layout;
                state.refresh(cx);
            }
            // A click updates the native selection before its background details load completes.
            // Reapplying unchanged workspace details here would select and scroll to the old row.
            if state.delegate().synced_selection != selected {
                state.delegate_mut().synced_selection = selected;
                if state.selected_row() != selected.map(|(_, row)| row) {
                    if let Some((_, row)) = selected {
                        state.set_selected_row(row, cx);
                    } else {
                        state.clear_selection(cx);
                    }
                }
            }
            cx.notify();
        });
    }

    pub(in crate::ui) fn reset_result_table(&self, cx: &mut Context<Self>) {
        self.result_table.update(cx, |state, cx| {
            state.delegate_mut().synced_selection = None;
            state.delegate_mut().pointer_scroll = None;
            state.clear_selection(cx);
            state.scroll_to_row(0, cx);
            state.scroll_to_col(0, cx);
        });
    }
}
