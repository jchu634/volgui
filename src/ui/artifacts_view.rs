use super::*;

#[derive(Clone)]
pub(super) struct ColumnResize {
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
    pub(super) fn resize_column(
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
    fn result_columns(&self) -> Vec<table::Column> {
        let mut groups = self.scope.iter().filter_map(|id| {
            self.case
                .as_ref()?
                .document
                .runs
                .iter()
                .find(|run| &run.id == id)
                .map(|run| ArtifactGroup::for_plugin(&run.plugin))
        });
        let group = groups
            .next()
            .filter(|first| groups.all(|group| group == *first));
        table::columns(group, &self.index.columns)
    }
    fn column_width(&self, column: &table::Column) -> Pixels {
        self.column_widths
            .get(&column.key)
            .copied()
            .unwrap_or(px(column.default_width()))
    }
    fn fit_column(&mut self, column: table::Column, window: &Window, cx: &mut Context<Self>) {
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
    pub(super) fn render_workspace(&self, cx: &mut Context<Self>) -> AnyElement {
        div()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(
                v_resizable("artifact-workspace-split")
                    .child(
                        resizable_panel()
                            .size_range(px(150.)..Pixels::MAX)
                            .child(self.render_results(cx)),
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
    fn render_results(&self, cx: &mut Context<Self>) -> AnyElement {
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
            .child(
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
                            .on_click(
                                cx.listener(|this, _, window, cx| this.export(false, window, cx)),
                            ),
                    ),
            )
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
                        let message = if self.loading {
                            "Loading results...".to_string()
                        } else if !self.query.read(cx).value().is_empty() {
                            "No results match your search.".to_string()
                        } else if let Some(run) = self.case.as_ref().and_then(|case| case.document.runs.iter().find(|run| self.scope.len() == 1 && self.scope.contains(&run.id))) {
                            match run.status {
                                RunStatus::Queued => "This analysis is queued. Results will appear after it runs.".into(),
                                RunStatus::Running => "This analysis is running. Results will appear when it finishes.".into(),
                                RunStatus::Failed | RunStatus::Interrupted | RunStatus::Cancelled => format!("This analysis {} and returned no results. See Run details for diagnostics.", run.status.label().to_lowercase()),
                                RunStatus::Completed => "This analysis completed without returning any results.".into(),
                            }
                        } else if self.scope.is_empty() {
                            "Select an analysis to view its results.".into()
                        } else {
                            "These analyses returned no results.".into()
                        };
                        body.child(div().absolute().top(px(48.)).left_0().right_0().px_4().text_sm().text_color(cx.theme().muted_foreground).child(message))
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
    fn render_result_rows(
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
    fn render_details(&self, cx: &mut Context<Self>) -> AnyElement {
        let record = self.selected.as_ref();
        let marked = self
            .case
            .as_ref()
            .and_then(|case| case.annotation(self.selected_run.as_deref()?, self.selected_row?))
            .is_some_and(|a| a.bookmarked);
        let mut tabs = div()
            .flex()
            .items_center()
            .gap_1()
            .px_3()
            .border_b_1()
            .border_color(cx.theme().border);
        for (id, label, tab) in [
            ("overview", "Overview", DetailTab::Overview),
            ("raw", "Raw JSON", DetailTab::Raw),
            ("notes", "Notes", DetailTab::Notes),
            ("diagnostics", "Run details", DetailTab::Diagnostics),
            ("files", "Extracted files", DetailTab::Files),
        ] {
            tabs = tabs.child(
                Button::new(id)
                    .small()
                    .ghost()
                    .label(label)
                    .selected(self.detail == tab)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.detail = tab;
                        cx.notify();
                    })),
            );
        }
        let mut content = div()
            .id("artifact-details-scroll")
            .track_scroll(&self.details_scroll)
            .overflow_scroll()
            .p_3()
            .size_full();
        match self.detail {
            DetailTab::Overview => {
                if let Some(record) = record {
                    let mut fields = div().flex().flex_wrap().gap_x_4().items_start().w_full();
                    for (i, (name, value)) in record.record.fields.iter().enumerate() {
                        let text = display_value(value);
                        let parent = self
                            .relations
                            .parent
                            .as_ref()
                            .filter(|_| name.eq_ignore_ascii_case("ppid"));
                        fields = fields.child(
                            div()
                                .flex()
                                .flex_basis(px(340.))
                                .flex_grow_1()
                                .min_w_0()
                                .max_w_full()
                                .when(text.chars().count() > 72 || text.contains('\n'), |field| {
                                    field.flex_basis(relative(1.))
                                })
                                .items_start()
                                .gap_2()
                                .py_1()
                                .border_b_1()
                                .border_color(cx.theme().border)
                                .child(
                                    div()
                                        .w(px(104.))
                                        .flex_shrink_0()
                                        .text_xs()
                                        .text_color(cx.theme().muted_foreground)
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(|this, _, window, cx| {
                                                window.focus(&this.workspace_focus, cx)
                                            }),
                                        )
                                        .child(SelectableText::new(
                                            ("field-name", i),
                                            name.clone(),
                                        )),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .text_sm()
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(|this, _, window, cx| {
                                                window.focus(&this.workspace_focus, cx)
                                            }),
                                        )
                                        .map(|cell| {
                                            if let Some(parent) = parent {
                                                let id = parent.id;
                                                cell.child(
                                                    record_link(
                                                        "parent-process",
                                                        format!("{text} · {}", parent.title),
                                                        cx,
                                                    )
                                                    .on_activate(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.load_record(id, cx)
                                                        },
                                                    )),
                                                )
                                                .into_any_element()
                                            } else {
                                                cell.child(SelectableText::new(
                                                    ("field-value", i),
                                                    text.clone(),
                                                ))
                                                .into_any_element()
                                            }
                                        }),
                                )
                                .child(
                                    Button::new(("copy-field", i))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::Copy)
                                        .tooltip("Copy value")
                                        .on_click(move |_, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                text.clone(),
                                            ))
                                        }),
                                ),
                        );
                    }
                    content = content.child(fields);
                    if let Some(parent) = self.relations.parent.as_ref().filter(|_| {
                        !record
                            .record
                            .fields
                            .keys()
                            .any(|k| k.eq_ignore_ascii_case("ppid"))
                    }) {
                        let id = parent.id;
                        content = content.child(
                            record_link(
                                "related-parent-process",
                                format!(
                                    "Parent: {} · PID {}",
                                    parent.title,
                                    parent.pid.as_deref().unwrap_or("")
                                ),
                                cx,
                            )
                            .on_activate(
                                cx.listener(move |this, _, _, cx| this.load_record(id, cx)),
                            ),
                        );
                    }
                    if !self.relations.children.is_empty() {
                        let children = self.relations.children.clone();
                        let height = px((children.len() as f32 * 28.).min(112.));
                        let list = uniform_list(
                            "process-children",
                            children.len(),
                            cx.processor(move |_, range: Range<usize>, _, cx| {
                                range
                                    .map(|i| {
                                        let child = &children[i];
                                        let id = child.id;
                                        Button::new(key("child-process", &id.to_string()))
                                            .small()
                                            .ghost()
                                            .justify_start()
                                            .h(px(28.))
                                            .label(format!(
                                                "{} · PID {}",
                                                child.title,
                                                child.pid.as_deref().unwrap_or("")
                                            ))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.load_record(id, cx)
                                            }))
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        )
                        .track_scroll(&self.relations_scroll)
                        .h_full();
                        content = content.child(
                            div()
                                .mt_2()
                                .child(heading(
                                    format!("CHILD PROCESSES ({})", self.relations.children.len()),
                                    cx,
                                ))
                                .child(
                                    div().relative().h(height).child(list).child(
                                        Scrollbar::vertical(&self.relations_scroll)
                                            .mode(ScrollbarMode::Always),
                                    ),
                                ),
                        );
                    }
                } else {
                    content=content.child(div().text_sm().text_color(cx.theme().muted_foreground).child("Select a result to inspect its fields. Add evidence or choose analyses to populate the table."));
                }
            }
            DetailTab::Raw => {
                if let Some(record) = record {
                    content = content.child(
                        div()
                            .flex()
                            .gap_2()
                            .mb_2()
                            .child(
                                Button::new("toggle-json-expansion")
                                    .xsmall()
                                    .ghost()
                                    .label(if self.raw_expand_all {
                                        "Collapse all"
                                    } else {
                                        "Expand all"
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.raw_expand_all = !this.raw_expand_all;
                                        this.raw_expanded.clear();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("copy-json")
                                    .xsmall()
                                    .ghost()
                                    .icon(IconName::Copy)
                                    .label("Copy JSON")
                                    .on_click({
                                        let json =
                                            serde_json::to_string_pretty(&record.record.fields)
                                                .unwrap_or_default();
                                        move |_, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                json.clone(),
                                            ))
                                        }
                                    }),
                            ),
                    );
                    for (key, value) in &record.record.fields {
                        let path = format!("/{}", key.replace('~', "~0").replace('/', "~1"));
                        content = content.child(self.json_node(&path, key, value, 0, cx));
                    }
                }
            }
            DetailTab::Notes => {
                content = content
                    .child(
                        Textarea::new(&self.note)
                            .accessibility_id("artifact-note")
                            .h(px(120.)),
                    )
                    .child(
                        Button::new("save-note")
                            .small()
                            .primary()
                            .label("Save note")
                            .disabled(record.is_none())
                            .on_click(cx.listener(|this, _, _, cx| this.annotate(false, cx))),
                    );
            }
            DetailTab::Files => {
                if let Some((case, run)) = self.case.as_ref().and_then(|case| {
                    case.document
                        .runs
                        .iter()
                        .find(|run| Some(&run.id) == self.selected_run.as_ref())
                        .map(|run| (case, run))
                }) {
                    let directory = case.run_dir(&run.id);
                    match volgui::extracted_files::list(&directory) {
                        Ok(files) if files.is_empty() => {
                            content = content.child("No extracted files. Run a dump plugin or enable its --dump option to extract files from memory.");
                        }
                        Ok(files) => {
                            let imhex = volgui::extracted_files::imhex();
                            if imhex.is_none() {
                                content = content.child(div().text_sm().child("ImHex was not found. Install it in its default location or add it to PATH to open files here."));
                            }
                            for (i, file) in files.into_iter().enumerate() {
                                let source = file.clone();
                                let mut row = div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .py_1()
                                    .child(
                                        div().flex_1().text_sm().child(
                                            file.strip_prefix(&directory)
                                                .unwrap_or(&file)
                                                .display()
                                                .to_string(),
                                        ),
                                    )
                                    .child(
                                        Button::new(("save-extracted", i))
                                            .small()
                                            .label("Save as...")
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.export_file(source.clone(), window, cx)
                                            })),
                                    );
                                if let Some(executable) = imhex.clone() {
                                    row = row.child(
                                        Button::new(("imhex-extracted", i))
                                            .small()
                                            .label("Open in ImHex")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                match volgui::extracted_files::open(
                                                    &executable,
                                                    &file,
                                                ) {
                                                    Ok(()) => {
                                                        this.message = "Opened in ImHex".into()
                                                    }
                                                    Err(error) => {
                                                        this.error = Some(format!(
                                                            "Could not open ImHex: {error}"
                                                        ))
                                                    }
                                                }
                                                cx.notify();
                                            })),
                                    );
                                }
                                content = content.child(row);
                            }
                        }
                        Err(error) => {
                            content =
                                content.child(format!("Could not list extracted files: {error}"))
                        }
                    }
                } else {
                    content = content.child("Select an analysis to view its extracted files.");
                }
            }
            DetailTab::Diagnostics => {
                if let Some(run) = self.case.as_ref().and_then(|c| {
                    c.document
                        .runs
                        .iter()
                        .find(|r| Some(&r.id) == self.selected_run.as_ref())
                }) {
                    let text = format!(
                        "{} · {} records · exit {:?}\n{}\nStarted {}\nFinished {}\n\n{}\n\n{}",
                        run.status.label(),
                        run.row_count,
                        run.exit_code,
                        run.engine_version,
                        run.started_at.as_deref().unwrap_or("Not started"),
                        run.finished_at.as_deref().unwrap_or("Not finished"),
                        serde_json::to_string_pretty(&run.command).unwrap_or_default(),
                        run.message
                    );
                    let output = self.case.as_ref().unwrap().run_dir(&run.id);
                    content = content
                        .child(
                            div()
                                .text_xs()
                                .font_family("Consolas")
                                .child(SelectableText::new("run-diagnostics", text)),
                        )
                        .child(
                            Button::new("show-output")
                                .small()
                                .label("Show output directory")
                                .on_click(move |_, _, cx| cx.reveal_path(&output)),
                        );
                }
            }
        }
        div()
            .size_full()
            .min_w_0()
            .min_h_0()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_1()
                    .child(
                        div().flex_1().min_w_0().text_sm().truncate().child(
                            record
                                .map(|r| r.record.title())
                                .unwrap_or_else(|| "Artifact details".into()),
                        ),
                    )
                    .when(record.is_some(), |header| {
                        header.child(
                            Button::new("bookmark")
                                .xsmall()
                                .ghost()
                                .icon(IconName::Bookmark)
                                .selected(marked)
                                .tooltip(if marked {
                                    "Remove bookmark"
                                } else {
                                    "Bookmark artifact"
                                })
                                .on_click(cx.listener(|this, _, _, cx| this.annotate(true, cx))),
                        )
                    }),
            )
            .child(tabs)
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(div().size_full().child(content))
                    .child(Scrollbar::vertical(&self.details_scroll).mode(ScrollbarMode::Always))
                    .child(Scrollbar::horizontal(&self.details_scroll).mode(ScrollbarMode::Always)),
            )
            .into_any_element()
    }
    fn json_node(
        &self,
        path: &str,
        name: &str,
        value: &serde_json::Value,
        depth: usize,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let expandable = value.is_array() || value.is_object();
        let expanded = self.raw_expand_all ^ self.raw_expanded.contains(path);
        let mut row = div()
            .flex()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| window.focus(&this.workspace_focus, cx)),
            )
            .items_center()
            .gap_2()
            .h(px(26.))
            .pl(px(depth as f32 * 16.))
            .text_xs()
            .font_family("Consolas");
        if expandable {
            let path = path.to_string();
            row = row.child(
                Button::new(key("json-toggle", &path))
                    .xsmall()
                    .ghost()
                    .icon(if expanded {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if !this.raw_expanded.remove(&path) {
                            this.raw_expanded.insert(path.clone());
                        }
                        cx.notify();
                    })),
            );
        } else {
            row = row.child(div().w(px(20.)));
        }
        let summary = match value {
            serde_json::Value::Array(v) => format!("[{} items]", v.len()),
            serde_json::Value::Object(v) => format!("{{{} fields}}", v.len()),
            _ => serde_json::to_string(value).unwrap_or_default(),
        };
        row = row.child(SelectableText::new(
            key("json-value", path),
            format!("{name}: {summary}"),
        ));
        let mut node = div().flex().flex_col().child(row);
        if expandable && expanded && depth < 64 {
            match value {
                serde_json::Value::Array(values) => {
                    for (i, value) in values.iter().enumerate() {
                        node = node.child(self.json_node(
                            &format!("{path}/{i}"),
                            &i.to_string(),
                            value,
                            depth + 1,
                            cx,
                        ));
                    }
                }
                serde_json::Value::Object(values) => {
                    for (key, value) in values {
                        node = node.child(self.json_node(
                            &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                            key,
                            value,
                            depth + 1,
                            cx,
                        ));
                    }
                }
                _ => {}
            }
        }
        node.into_any_element()
    }
}
