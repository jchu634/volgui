// Renders artifact results and record details.
use super::*;

#[derive(Clone)]
pub(in crate::ui) struct ColumnResize {
    column: String,
    width: Pixels,
    origin: Rc<Cell<Pixels>>,
}
struct ResizeGhost;
impl Render for ResizeGhost {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}
impl Workspace {
    pub(in crate::ui) fn resize_column(
        &mut self,
        event: &DragMoveEvent<ColumnResize>,
        cx: &mut Context<Self>,
    ) {
        let drag = event.drag(cx);
        self.column_fit_epoch.fetch_add(1, Ordering::Relaxed);
        let width =
            (drag.width + event.event.position.x - drag.origin.get()).clamp(px(72.), px(1400.));
        self.column_widths.insert(drag.column.clone(), width);
        cx.notify();
    }
    pub(in crate::ui) fn result_group(&self) -> Option<ArtifactGroup> {
        if self.scope.is_empty() && self.scope_label == self.browser_group.label() {
            return Some(self.browser_group);
        }
        let mut groups = self.scope.iter().filter_map(|id| {
            self.case
                .as_ref()?
                .document
                .runs
                .iter()
                .find(|run| &run.id == id)
                .map(|run| ArtifactGroup::for_plugin(&run.plugin))
        });
        groups
            .next()
            .filter(|first| groups.all(|group| group == *first))
    }
    pub(in crate::ui) fn result_columns(&self) -> Vec<table::Column> {
        table::columns(self.result_group(), &self.index.columns)
    }
    pub(in crate::ui) fn column_width(&self, column: &table::Column) -> Pixels {
        self.column_widths
            .get(&column.key)
            .copied()
            .unwrap_or(px(column.default_width()))
    }
    pub(in crate::ui) fn fit_column(
        &mut self,
        column: table::Column,
        window: &Window,
        cx: &mut Context<Self>,
    ) {
        if self.loading {
            return;
        }
        let Some(store) = self.store() else { return };
        let ids = self.index.ids.clone();
        let query_token = self.query_epoch.clone();
        let query_epoch = query_token.load(Ordering::Relaxed);
        let fit_token = self.column_fit_epoch.clone();
        let fit_epoch = fit_token.fetch_add(1, Ordering::Relaxed) + 1;
        let text_system = cx.text_system().clone();
        let text_style = window.text_style();
        let font_size = window.rem_size() * 0.75;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let text_system = WindowTextSystem::new(text_system);
            let measure = |text: &str| {
                text.lines()
                    .map(|line| {
                        text_system
                            .shape_line(
                                line.to_owned().into(),
                                font_size,
                                &[text_style.to_run(line.len())],
                                None,
                            )
                            .width
                    })
                    .max()
                    .unwrap_or_default()
            };
            let result = (|| {
                let mut width = measure(&format!("{} ↓", column.label));
                for chunk in ids.chunks(256) {
                    if query_token.load(Ordering::Relaxed) != query_epoch
                        || fit_token.load(Ordering::Relaxed) != fit_epoch
                    {
                        return Ok(None);
                    }
                    for record in store.fetch(chunk)? {
                        width = width.max(measure(&column.text(&record.record)));
                    }
                }
                Ok(Some((width + px(32.)).max(px(72.))))
            })();
            let result = match result {
                Ok(Some(width)) => Ok(width),
                Err(error) => Err(error),
                Ok(None) => return,
            };
            let _ = tx.send(Event::ColumnFitted(
                query_epoch,
                fit_epoch,
                column.key,
                result,
            ));
        });
    }
    pub(in crate::ui) fn render_workspace(&self, cx: &mut Context<Self>) -> AnyElement {
        let results = if self.hex_visible {
            h_resizable("artifact-hex-split")
                .child(
                    resizable_panel()
                        .size_range(px(260.)..Pixels::MAX)
                        .child(self.render_results(cx)),
                )
                .child(
                    resizable_panel()
                        .size(px(660.))
                        .size_range(px(300.)..Pixels::MAX)
                        .child(self.render_hex_panel(cx)),
                )
                .into_any_element()
        } else {
            self.render_results(cx)
        };
        div()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(
                v_resizable("artifact-workspace-split")
                    .child(
                        resizable_panel()
                            .size_range(px(150.)..Pixels::MAX)
                            .child(results),
                    )
                    .child(
                        resizable_panel()
                            .size(px(290.))
                            .size_range(px(150.)..px(1000.))
                            .fixed()
                            .child(self.render_details(cx)),
                    ),
            )
            .into_any_element()
    }
    pub(in crate::ui) fn render_results(&self, cx: &mut Context<Self>) -> AnyElement {
        match self.result_group() {
            Some(ArtifactGroup::Processes) => return self.render_processes(cx),
            Some(ArtifactGroup::Files) => return self.render_files(cx),
            _ => {}
        }
        let columns = self.result_columns();
        let single_column = columns.len() == 1;
        let width: Pixels = columns.iter().map(|c| self.column_width(c)).sum();
        let mut headers = div()
            .flex()
            .h(px(32.))
            .w(width)
            .min_w_full()
            .bg(cx.theme().muted);
        for column in &columns {
            let name = column.key.clone();
            let label = column.label.clone();
            let suffix = self
                .sort
                .as_ref()
                .filter(|(c, _)| c == &column.key)
                .map_or("", |(_, descending)| if *descending { " ↓" } else { " ↑" });
            let drag = ColumnResize {
                column: name.clone(),
                width: self.column_width(column),
                origin: self.column_drag_origin.clone(),
            };
            headers = headers.child(
                div()
                    .id(key("result-header", &column.key))
                    .relative()
                    .flex_shrink_0()
                    .w(self.column_width(column))
                    .when(single_column, |cell| cell.flex_grow_1())
                    .h_full()
                    .flex()
                    .items_center()
                    .px_3()
                    .text_xs()
                    .child(
                        div()
                            .id(key("sort-column", &column.key))
                            .flex_1()
                            .truncate()
                            .cursor_pointer()
                            .child(format!("{label}{suffix}"))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                let descending =
                                    this.sort.as_ref().is_some_and(|(c, d)| c == &name && !*d);
                                this.sort = Some((name.clone(), descending));
                                this.start_query(cx);
                            })),
                    )
                    .child(
                        resize_handle(key("resize-column", &column.key), Axis::Horizontal)
                            .inside(HandleEdge::Trailing)
                            .on_mouse_down(MouseButton::Left, {
                                let origin = self.column_drag_origin.clone();
                                move |event, _, _| origin.set(event.position.x)
                            })
                            .on_drag(drag, |_, _, _, cx| cx.new(|_| ResizeGhost))
                            .on_double_click({
                                let column = column.clone();
                                cx.listener(move |this, _, window, cx| {
                                    this.fit_column(column.clone(), window, cx);
                                })
                            }),
                    ),
            );
        }
        let list = uniform_list(
            "artifact-results-virtual",
            self.index.ids.len(),
            cx.processor(|this, range, _, cx| this.render_result_rows(range, cx)),
        )
        .track_scroll(&self.result_scroll)
        .map(|mut list| {
            list.style().restrict_scroll_to_axis = Some(true);
            list
        })
        .w(width)
        .min_w_full()
        .h_full();
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(self.render_results_toolbar(cx))
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(
                        div()
                            .id("table-horizontal-scroll")
                            .track_scroll(&self.table_x_scroll)
                            .overflow_x_scroll()
                            .restrict_scroll_to_axis()
                            .size_full()
                            .pb(px(12.))
                            .child(
                                div()
                                    .w(width)
                                    .min_w_full()
                                    .h_full()
                                    .flex()
                                    .flex_col()
                                    .child(headers)
                                    .child(
                                        div()
                                            .id("artifact-results-list")
                                            .role(Role::ListBox)
                                            .aria_label("Artifact results")
                                            .flex_1()
                                            .min_h_0()
                                            .child(list),
                                    ),
                            ),
                    )
                    .when(self.index.ids.is_empty(), |body| {
                        let message = self.results_empty_message(cx);
                        body.child(
                            div()
                                .absolute()
                                .top(px(48.))
                                .left_0()
                                .right_0()
                                .px_4()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(message),
                        )
                    })
                    .child(Scrollbar::horizontal(&self.table_x_scroll).mode(ScrollbarMode::Always))
                    .child(
                        // The list spans all columns; anchor its scrollbar to the visible body.
                        div()
                            .absolute()
                            .top(px(32.))
                            .bottom(px(12.))
                            .left_0()
                            .right_0()
                            .child(
                                Scrollbar::vertical(&self.result_scroll)
                                    .viewport_from_layout()
                                    .mode(ScrollbarMode::Always),
                            ),
                    ),
            )
            .into_any_element()
    }
    pub(in crate::ui) fn render_result_rows(
        &mut self,
        range: Range<usize>,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        self.request_rows(range.clone());
        let columns = self.result_columns();
        let single_column = columns.len() == 1;
        let width: Pixels = columns.iter().map(|c| self.column_width(c)).sum();
        range
            .filter_map(|i| self.index.ids.get(i).copied())
            .map(|id| {
                let record = self.row_cache.get(&id);
                let mut row = div()
                    .id(("result-row", id as u64))
                    .role(Role::ListBoxOption)
                    .aria_label(
                        record
                            .map(|r| r.record.title())
                            .unwrap_or_else(|| "Loading artifact".into()),
                    )
                    .aria_selected(self.selected.as_ref().is_some_and(|r| r.id == id))
                    .flex()
                    .items_center()
                    .h(px(30.))
                    .w(width)
                    .min_w_full()
                    .cursor_pointer()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _, window, cx| window.focus(&this.workspace_focus, cx)),
                    )
                    .bg(if self.selected.as_ref().is_some_and(|r| r.id == id) {
                        cx.theme().accent
                    } else {
                        cx.theme().background
                    })
                    .hover(|s| s.bg(cx.theme().muted))
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .on_click(cx.listener(move |this, _, _, cx| this.load_record(id, cx)));
                for column in &columns {
                    let value = record
                        .map(|r| column.text(&r.record))
                        .unwrap_or_else(|| "...".into());
                    let parent = column.key.eq_ignore_ascii_case("ppid")
                        && !value.is_empty()
                        && value != "0"
                        && !self.group_runs(ArtifactGroup::Processes).is_empty();
                    row =
                        row.child(
                            div()
                                .w(self.column_width(column))
                                .when(single_column, |cell| cell.flex_grow_1())
                                .h_full()
                                .flex()
                                .items_center()
                                .whitespace_nowrap()
                                .flex_shrink_0()
                                .px_3()
                                .text_xs()
                                .overflow_hidden()
                                .map(|cell| {
                                    if parent {
                                        cell.child(
                                            record_link(
                                                key("parent-cell", &format!("{id}-{}", column.key)),
                                                value.clone(),
                                                cx,
                                            )
                                            .on_activate(cx.listener(move |this, _, _, cx| {
                                                cx.stop_propagation();
                                                this.open_process(value.clone(), cx);
                                            })),
                                        )
                                        .into_any_element()
                                    } else {
                                        cell.child(SelectableText::new(
                                            key("result-text", &format!("{id}-{}", column.key)),
                                            value,
                                        ))
                                        .into_any_element()
                                    }
                                }),
                        );
                }
                row.into_any_element()
            })
            .collect()
    }
    pub(in crate::ui) fn render_results_toolbar(&self, cx: &mut Context<Self>) -> Div {
        div()
            .flex()
            .items_center()
            .gap_3()
            .px_3()
            .py_2()
            .child(div().flex_1().min_w_0().text_sm().truncate().child(format!(
                "{} · {} results{}",
                self.scope_label,
                self.index.ids.len(),
                if self.loading { " · searching" } else { "" }
            )))
            .child(
                div().w(px(260.)).child(
                    Input::new(&self.query)
                        .id("result-search")
                        .aria_label("Search artifacts")
                        .small()
                        .cleanable(true),
                ),
            )
            .child(
                Button::new("export-csv")
                    .small()
                    .ghost()
                    .label("Export CSV")
                    .disabled(self.scope.is_empty())
                    .on_click(cx.listener(|this, _, window, cx| this.export(false, window, cx))),
            )
    }
    pub(in crate::ui) fn results_empty_message(&self, cx: &App) -> String {
        if self.loading {
            "Loading results...".to_string()
        } else if !self.query.read(cx).value().is_empty() {
            "No results match your search.".to_string()
        } else if let Some(run) = self.case.as_ref().and_then(|case| {
            case.document
                .runs
                .iter()
                .find(|run| self.scope.len() == 1 && self.scope.contains(&run.id))
        }) {
            match run.status {
                RunStatus::Queued => {
                    "This analysis is queued. Results will appear after it runs.".into()
                }
                RunStatus::Running => {
                    "This analysis is running. Results will appear when it finishes.".into()
                }
                RunStatus::Failed | RunStatus::Interrupted | RunStatus::Cancelled => format!(
                    "This analysis {} and returned no results. See Run details for diagnostics.",
                    run.status.label().to_lowercase()
                ),
                RunStatus::Completed => {
                    "This analysis completed without returning any results.".into()
                }
            }
        } else if self.scope.is_empty() {
            "Select an analysis to view its results.".into()
        } else {
            "These analyses returned no results.".into()
        }
    }
}
