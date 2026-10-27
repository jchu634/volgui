// The hierarchy is a pinned DataTable column; metadata scrolls to its right.
use super::*;
use volgui::result_tree::TreeNodeKind;

pub(in crate::ui) struct TreeTable {
    workspace: WeakEntity<Workspace>,
    columns: Vec<table::Column>,
    pub(in crate::ui) layout: Vec<DataColumn>,
    synced_selection: Option<(usize, usize)>,
    pointer_scroll: Option<Point<Pixels>>,
}

impl TreeTable {
    pub(in crate::ui) fn new(workspace: WeakEntity<Workspace>) -> Self {
        Self {
            workspace,
            columns: vec![],
            layout: vec![],
            synced_selection: None,
            pointer_scroll: None,
        }
    }

    fn render_name(&self, workspace: &Workspace, row: usize, cx: &App) -> AnyElement {
        let Some(&(i, depth)) = workspace.result_tree.visible.get(row) else {
            return div().into_any_element();
        };
        let node = &workspace.result_tree.nodes[i];
        let branch = workspace.result_tree.has_children(i);
        let expanded = workspace.result_tree.expanded(i);
        let icon = match node.kind {
            TreeNodeKind::Process if node.pid.is_some() => IconName::Cpu,
            TreeNodeKind::Process | TreeNodeKind::Module => IconName::Layers,
            TreeNodeKind::File | TreeNodeKind::RegistryValue => IconName::File,
            TreeNodeKind::Directory | TreeNodeKind::RegistryKey => IconName::Folder,
        };
        let weak = self.workspace.clone();
        let toggle = if branch {
            app_button(("tree-table-toggle", i))
                .ghost()
                .xsmall()
                .icon(if expanded {
                    IconName::ChevronDown
                } else {
                    IconName::ChevronRight
                })
                .tooltip(if expanded {
                    "Collapse branch"
                } else {
                    "Expand branch"
                })
                .on_click(move |_, window, cx| {
                    cx.stop_propagation();
                    let _ = weak.update(cx, |workspace, cx| {
                        window.focus(&workspace.workspace_focus, cx);
                        workspace.tree_cursor = Some(i);
                        workspace.result_tree.toggle(i);
                        cx.notify();
                    });
                })
                .into_any_element()
        } else {
            div().w(px(24.)).flex_shrink_0().into_any_element()
        };
        let label = node.label.clone();
        let mut name = div()
            .flex()
            .items_center()
            .gap_2()
            .size_full()
            .min_w_0()
            .pl(px(depth as f32 * 18.))
            .child(toggle)
            .child(Icon::new(icon).size_4().flex_shrink_0())
            .child(
                div()
                    .id(("tree-table-name", i))
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .tooltip(move |window, cx| Tooltip::new(label.clone()).build(window, cx))
                    .child(node.label.clone()),
            );
        if matches!(node.kind, TreeNodeKind::File)
            && let Some(id) = node.record_id
        {
            let weak = self.workspace.clone();
            name = name
                .when_some(workspace.file_recovery_states.get(&id), |name, state| {
                    name.child(
                        div()
                            .flex_shrink_0()
                            .text_color(cx.theme().muted_foreground)
                            .child(state.label()),
                    )
                })
                .child(
                    app_button(("tree-table-show-file", i))
                        .xsmall()
                        .label("Show in Files")
                        .disabled(!workspace.row_cache.contains_key(&id))
                        .on_click(move |_, window, cx| {
                            cx.stop_propagation();
                            let _ = weak.update(cx, |workspace, cx| {
                                workspace.show_file_in_files(id, window, cx)
                            });
                        }),
                );
        }
        name.into_any_element()
    }
}

impl TableDelegate for TreeTable {
    fn columns_count(&self, _: &App) -> usize {
        self.layout.len()
    }

    fn rows_count(&self, cx: &App) -> usize {
        self.workspace
            .upgrade()
            .map_or(0, |workspace| workspace.read(cx).result_tree.visible.len())
    }

    fn column(&self, col: usize, _: &App) -> DataColumn {
        self.layout[col].clone()
    }

    fn render_th(
        &mut self,
        col: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div().text_xs().child(self.layout[col].name.clone())
    }

    fn visible_rows_changed(
        &mut self,
        range: Range<usize>,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let workspace = self.workspace.clone();
        cx.defer(move |cx| {
            let _ = workspace.update(cx, |workspace, _| workspace.request_tree_rows(range));
        });
    }

    fn render_tr(
        &mut self,
        row: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let workspace = self.workspace.upgrade();
        let state = workspace.as_ref().map(|workspace| workspace.read(cx));
        let node = state.and_then(|state| {
            state
                .result_tree
                .visible
                .get(row)
                .map(|(i, depth)| (*i, *depth, &state.result_tree.nodes[*i]))
        });
        let mut element = div().id(("tree-table-row", row)).text_xs();
        if let Some((i, depth, node)) = node {
            let partial = node
                .record_id
                .is_some_and(|id| state.is_some_and(|state| state.is_partial_record(id)));
            element = element
                .aria_label(if partial {
                    format!("Partial match · {}", node.label)
                } else {
                    node.label.clone()
                })
                .when(partial, partial_matches::highlight_row)
                .aria_level(depth + 1)
                .when(
                    state.is_some_and(|state| state.result_tree.has_children(i)),
                    |row| {
                        row.aria_expanded(state.is_some_and(|state| state.result_tree.expanded(i)))
                    },
                );
            let missing = state.is_some_and(|state| {
                [node.record_id, state.result_tree.detail_node(i).record_id]
                    .into_iter()
                    .flatten()
                    .any(|id| !state.row_cache.contains_key(&id))
            });
            if missing {
                let table = cx.entity().downgrade();
                let workspace = self.workspace.clone();
                cx.defer(move |cx| {
                    if let Some(table) = table.upgrade() {
                        let range = table.read(cx).visible_range().rows().clone();
                        let _ =
                            workspace.update(cx, |workspace, _| workspace.request_tree_rows(range));
                    }
                });
            }
        }
        element
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|state, _, window, cx| {
                    state.focus_handle(cx).focus(window, cx);
                    let offset = state.vertical_scroll_handle.0.borrow().base_handle.offset();
                    state.delegate_mut().pointer_scroll = Some(offset);
                }),
            )
            .on_click(cx.listener(|state, event, window, cx| {
                let offset = state.delegate_mut().pointer_scroll.take();
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

    fn render_td(
        &mut self,
        row: usize,
        col: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        if col == 0 {
            return self
                .workspace
                .upgrade()
                .map(|workspace| self.render_name(workspace.read(cx), row, cx))
                .unwrap_or_else(|| div().into_any_element());
        }
        div()
            .text_xs()
            .whitespace_nowrap()
            .overflow_hidden()
            .child(SelectableText::new(
                ("tree-table-text", row * self.layout.len() + col),
                self.cell_text(row, col, cx),
            ))
            .into_any_element()
    }

    fn cell_text(&self, row: usize, col: usize, cx: &App) -> String {
        let Some(workspace) = self.workspace.upgrade() else {
            return String::new();
        };
        let workspace = workspace.read(cx);
        let Some(&(i, _)) = workspace.result_tree.visible.get(row) else {
            return String::new();
        };
        if col == 0 {
            return workspace.result_tree.nodes[i].label.clone();
        }
        let Some(column) = self.columns.get(col - 1) else {
            return String::new();
        };
        let source = workspace.result_tree.detail_node(i);
        if column.label == "PID"
            && let Some(pid) = &source.pid
        {
            return pid.clone();
        }
        source
            .record_id
            .map(|id| {
                workspace
                    .row_cache
                    .get(&id)
                    .map(|record| column.text(&record.record))
                    .unwrap_or_else(|| "...".into())
            })
            .unwrap_or_default()
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div().p_4().text_sm().child(
            self.workspace
                .upgrade()
                .map(|workspace| workspace.read(cx).results_empty_message(cx))
                .unwrap_or_default(),
        )
    }
}

impl Workspace {
    fn request_tree_rows(&mut self, range: Range<usize>) {
        let mut ids: Vec<_> = self
            .result_tree
            .visible
            .get(range)
            .unwrap_or(&[])
            .iter()
            .flat_map(|(i, _)| {
                [
                    self.result_tree.nodes[*i].record_id,
                    self.result_tree.detail_node(*i).record_id,
                ]
            })
            .flatten()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        self.request_record_ids(ids);
    }

    pub(in crate::ui) fn sync_tree_table(&self, group: ArtifactGroup, cx: &mut Context<Self>) {
        let columns = table::tree_columns(group, &self.index.columns);
        let max_tree_width = (self.tree_viewport_width - px(160.)).max(px(240.));
        let hierarchy_key = format!("tree:{group:?}:hierarchy");
        let hierarchy_fraction = if group == ArtifactGroup::Processes {
            2. / 3.
        } else {
            0.5
        };
        let hierarchy_width = self
            .column_widths
            .get(&hierarchy_key)
            .copied()
            .unwrap_or(self.tree_viewport_width * hierarchy_fraction)
            .clamp(px(240.), max_tree_width);
        let label = match group {
            ArtifactGroup::Processes => "Process / file",
            ArtifactGroup::Registry => "Registry key / value",
            _ => "Process / module",
        };
        let mut layout = vec![
            DataColumn::new(hierarchy_key, label)
                .width(hierarchy_width)
                .min_width(px(240.))
                .max_width(max_tree_width)
                .fixed_left()
                .movable(false),
        ];
        layout.extend(columns.iter().map(|column| {
            let key = format!("tree:{group:?}:{}", column.key);
            let width = self
                .column_widths
                .get(&key)
                .copied()
                .unwrap_or(px(column.default_width()));
            DataColumn::new(key, column.label.clone())
                .width(width)
                .min_width(px(72.))
                .max_width(px(1400.))
                .movable(false)
        }));
        let selected = self.tree_cursor.and_then(|node| {
            self.result_tree
                .visible
                .iter()
                .position(|(i, _)| *i == node)
                .map(|row| (node, row))
        });
        self.tree_table.update(cx, |state, cx| {
            let changed = state.delegate().layout.len() != layout.len()
                || state.delegate().layout.iter().zip(&layout).any(|(a, b)| {
                    a.key != b.key || a.width != b.width || a.max_width != b.max_width
                });
            state.delegate_mut().columns = columns;
            if changed {
                state.delegate_mut().layout = layout;
                state.refresh(cx);
            }
            if state.delegate().synced_selection != selected {
                state.delegate_mut().synced_selection = selected;
                if state.selected_row() != selected.map(|(_, row)| row) {
                    if let Some((_, row)) = selected {
                        state.set_selected_row(row, cx);
                        state
                            .vertical_scroll_handle
                            .scroll_to_item(row, ScrollStrategy::Nearest);
                    } else {
                        state.clear_selection(cx);
                    }
                }
            }
            cx.notify();
        });
    }

    pub(in crate::ui) fn scroll_tree_to_row(&self, row: usize, cx: &mut Context<Self>) {
        if self.result_group() == Some(ArtifactGroup::Files) {
            self.result_scroll
                .scroll_to_item(row, ScrollStrategy::Nearest);
        } else {
            self.tree_table.update(cx, |state, cx| {
                state
                    .vertical_scroll_handle
                    .scroll_to_item(row, ScrollStrategy::Nearest);
                cx.notify();
            });
        }
    }

    pub(in crate::ui) fn reset_tree_table(&self, cx: &mut Context<Self>) {
        self.tree_table.update(cx, |state, cx| {
            state.delegate_mut().synced_selection = None;
            state.delegate_mut().pointer_scroll = None;
            state.clear_selection(cx);
            state.scroll_to_row(0, cx);
            state.scroll_to_col(1, cx);
        });
    }
}
