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

struct ColumnFilter {
    workspace: WeakEntity<Workspace>,
    scope: Vec<String>,
    column: String,
    label: String,
    values: Option<Result<Arc<Vec<String>>, String>>,
    search: Entity<InputState>,
    matches: Arc<Vec<usize>>,
    scroll: UniformListScrollHandle,
}

impl ColumnFilter {
    fn new(
        workspace: WeakEntity<Workspace>,
        store: ResultStore,
        scope: Vec<String>,
        column: String,
        label: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        if let Some(workspace) = workspace.upgrade() {
            cx.observe(&workspace, |_, _, cx| cx.notify()).detach();
        }
        let search = field("", "Search values...", window, cx);
        cx.subscribe(&search, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                this.filter_values(cx);
                cx.notify();
            }
        })
        .detach();
        let runs = scope.clone();
        let field = column.clone();
        let load = cx
            .background_executor()
            .spawn(async move { store.filter_values(&runs, &field).map(Arc::new) });
        cx.spawn(async move |this, cx| {
            let values = load.await;
            let _ = this.update(cx, |this, cx| {
                this.values = Some(values);
                this.filter_values(cx);
                cx.notify();
            });
        })
        .detach();
        Self {
            workspace,
            scope,
            column,
            label,
            values: None,
            search,
            matches: Arc::new(Vec::new()),
            scroll: UniformListScrollHandle::default(),
        }
    }

    fn filter_values(&mut self, cx: &App) {
        let needle = self.search.read(cx).value().to_lowercase();
        self.matches = Arc::new(match &self.values {
            Some(Ok(values)) => values
                .iter()
                .enumerate()
                .filter(|(_, value)| {
                    let label = if value.is_empty() {
                        "N.A."
                    } else {
                        value.as_str()
                    };
                    label.to_lowercase().contains(&needle)
                })
                .map(|(i, _)| i)
                .collect(),
            _ => Vec::new(),
        });
        self.scroll = UniformListScrollHandle::default();
    }
}

impl Render for ColumnFilter {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let panel = div()
            .id("column-filter-panel")
            .flex()
            .flex_col()
            .w(px(280.))
            .text_sm();
        let values = match &self.values {
            None => return panel.p_2().child("Loading filters...").into_any_element(),
            Some(Err(error)) => {
                return panel
                    .p_2()
                    .child(format!("Could not load filters: {error}"))
                    .into_any_element();
            }
            Some(Ok(values)) => values.clone(),
        };
        let matches = self.matches.clone();
        let height = px((matches.len().clamp(1, 11) * 28) as f32);
        let all_checked = self
            .workspace
            .upgrade()
            .is_some_and(|workspace| !workspace.read(cx).column_filters.contains_key(&self.column));
        panel
            .on_click(|_, _, cx| cx.stop_propagation())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div().font_weight(FontWeight::BOLD).child(
                            Checkbox::new("filter-all")
                                .label(self.label.clone())
                                .checked(all_checked)
                                .on_change(cx.listener(|this, checked, _, cx| {
                                    cx.stop_propagation();
                                    let _ = this.workspace.update(cx, |state, cx| {
                                        if state.scope != this.scope {
                                            return;
                                        }
                                        if *checked {
                                            state.column_filters.remove(&this.column);
                                        } else {
                                            state
                                                .column_filters
                                                .insert(this.column.clone(), BTreeSet::new());
                                        }
                                        state.start_query(cx);
                                    });
                                })),
                        ),
                    )
                    .child(
                        Input::new(&self.search)
                            .id("filter-search")
                            .aria_label(format!("Search {} values", self.label))
                            .small()
                            .flex_1()
                            .min_w_0(),
                    ),
            )
            .child(div().h(px(1.)).w_full().my_1().bg(cx.theme().border))
            .child(
                uniform_list(
                    "filter-values",
                    matches.len(),
                    cx.processor(move |this, range: Range<usize>, _, cx| {
                        range
                            .map(|i| {
                                let i = matches[i];
                                let value = values[i].clone();
                                let checked = this.workspace.upgrade().is_some_and(|workspace| {
                                    workspace
                                        .read(cx)
                                        .column_filters
                                        .get(&this.column)
                                        .is_none_or(|selected| selected.contains(&value))
                                });
                                let all = values.clone();
                                div().h(px(28.)).w_full().overflow_hidden().child(
                                    Checkbox::new(("filter-value", i))
                                        .label(if value.is_empty() {
                                            "N.A.".into()
                                        } else {
                                            value.clone()
                                        })
                                        .checked(checked)
                                        .on_change(cx.listener(move |this, checked, _, cx| {
                                            cx.stop_propagation();
                                            let _ = this.workspace.update(cx, |state, cx| {
                                                if state.scope != this.scope {
                                                    return;
                                                }
                                                let selected = state
                                                    .column_filters
                                                    .entry(this.column.clone())
                                                    .or_insert_with(|| {
                                                        all.iter().cloned().collect()
                                                    });
                                                if *checked {
                                                    selected.insert(value.clone());
                                                } else {
                                                    selected.remove(&value);
                                                }
                                                if selected.len() == all.len() {
                                                    state.column_filters.remove(&this.column);
                                                }
                                                state.start_query(cx);
                                            });
                                        })),
                                )
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(&self.scroll)
                .h(height)
                .w_full(),
            )
            .when(self.matches.is_empty(), |panel| {
                panel.child(div().p_2().child("No matching values"))
            })
            .into_any_element()
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

    fn render_th(
        &mut self,
        col: usize,
        window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let column = &self.columns[col];
        let weak = self.workspace.clone();
        let filterable = weak.upgrade().is_some_and(|workspace| {
            matches!(
                workspace.read(cx).result_group(),
                Some(ArtifactGroup::Web | ArtifactGroup::Downloads | ArtifactGroup::Quarantine)
            )
        }) && matches!(
            column.key.as_str(),
            "PID"
                | "Browser"
                | "Kind"
                | "Domain"
                | "Finding"
                | "Filename"
                | "Remote IP"
                | "Remote port"
                | "Scope"
                | "Antivirus"
                | "Evidence status"
                | "Execution evidence"
                | "Origin evidence"
        );
        let header = div()
            .flex()
            .items_center()
            .gap_1()
            .text_xs()
            .child(column.label.clone());
        if !filterable {
            return header.into_any_element();
        }
        let label = column.label.clone();
        let column = column.key.clone();
        let active = weak
            .upgrade()
            .is_some_and(|workspace| workspace.read(cx).column_filters.contains_key(&column));
        let panel_state =
            window.use_keyed_state(key("column-filter-panel", &column), cx, |_, _| {
                None::<Entity<ColumnFilter>>
            });
        let close_state = panel_state.clone();
        header
            .child(
                Popover::new(key("column-filter-popover", &column))
                    .anchor(Anchor::TopLeft)
                    .on_open_change(move |open, _, cx| {
                        if !open {
                            close_state.update(cx, |panel, _| *panel = None);
                        }
                    })
                    .trigger(
                        app_button(key("column-filter", &column))
                            .ghost()
                            .xsmall()
                            .icon(IconName::ChevronDown)
                            .selected(active)
                            .tooltip(format!("Filter {label}"))
                            .accessibility_label(format!("Filter {label}")),
                    )
                    .content(move |_, window, cx| {
                        if let Some(panel) = panel_state.read(cx) {
                            return panel.clone().into_any_element();
                        }
                        let Some(workspace) = weak.upgrade() else {
                            return div().into_any_element();
                        };
                        let state = workspace.read(cx);
                        let Some(store) = state.store() else {
                            return div().into_any_element();
                        };
                        let scope = state.scope.clone();
                        let panel = cx.new(|cx| {
                            ColumnFilter::new(
                                weak.clone(),
                                store,
                                scope,
                                column.clone(),
                                label.clone(),
                                window,
                                cx,
                            )
                        });
                        panel_state.update(cx, |state, _| *state = Some(panel.clone()));
                        panel.into_any_element()
                    }),
            )
            .into_any_element()
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
                .is_some_and(|value| value.parse::<u64>().is_ok_and(|pid| pid != 0))
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
        self.reset_tree_table(cx);
        self.result_table.update(cx, |state, cx| {
            state.delegate_mut().synced_selection = None;
            state.delegate_mut().pointer_scroll = None;
            state.clear_selection(cx);
            state.scroll_to_row(0, cx);
            state.scroll_to_col(0, cx);
        });
    }
}
