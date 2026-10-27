// Renders artifact results and record details.
use super::*;
use gpui_kit::base::ElementExt as _;

impl Workspace {
    pub(in crate::ui) fn supports_content_sidebar(&self) -> bool {
        self.view == View::Workspace
            && matches!(
                self.result_group(),
                Some(
                    ArtifactGroup::Processes
                        | ArtifactGroup::Files
                        | ArtifactGroup::Applications
                        | ArtifactGroup::Network
                        | ArtifactGroup::Memory
                        | ArtifactGroup::Strings
                )
            )
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
            .unwrap_or_else(|| {
                let default = px(column.default_width());
                let fills_space = matches!(
                    (self.result_group(), column.key.as_str()),
                    (Some(ArtifactGroup::Strings), "Context")
                        | (Some(ArtifactGroup::Downloads), "URL")
                );
                if fills_space {
                    let other_widths: Pixels = self
                        .result_columns()
                        .iter()
                        .filter(|other| other.key != column.key)
                        .map(|column| self.column_width(column))
                        .sum();
                    (self.result_viewport_width - px(2.) - other_widths).max(default)
                } else {
                    default
                }
            })
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
                    for record in store.fetch_enriched(chunk)? {
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
        if self.result_group() == Some(ArtifactGroup::Applications) {
            return self.render_application_memory(cx);
        }
        if self.result_group() == Some(ArtifactGroup::Network) {
            return div()
                .size_full()
                .min_w_0()
                .min_h_0()
                .overflow_hidden()
                .child(
                    v_resizable("network-workspace-split")
                        .child(
                            resizable_panel()
                                .size_range(px(240.)..Pixels::MAX)
                                .child(self.render_network(cx)),
                        )
                        .child(
                            resizable_panel()
                                .size(px(240.))
                                .size_range(px(150.)..px(1000.))
                                .fixed()
                                .child(self.render_details(cx)),
                        ),
                )
                .into_any_element();
        }
        let results = if self.supports_content_sidebar() && self.content_sidebar_visible {
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
            Some(group @ (ArtifactGroup::Registry | ArtifactGroup::Modules)) => {
                return self.render_artifact_tree(group, cx);
            }
            _ => {}
        }
        self.sync_result_table(cx);
        self.restore_table_scroll(
            scroll_state::ResultTableKind::Results,
            &self.result_table,
            cx,
        );
        let workspace = cx.entity().downgrade();
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(self.render_results_toolbar(cx))
            .child(self.render_investigation_tools(cx))
            .child(
                div()
                    .id("artifact-results-table")
                    .p_3()
                    .aria_label("Artifact results")
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(
                        div()
                            .size_full()
                            .child(
                                DataTable::new(&self.result_table)
                                    .small()
                                    .header_row_height(px(32.)),
                            )
                            .on_prepaint(move |bounds, _, cx| {
                                cx.defer(move |cx| {
                                    let _ = workspace.update(cx, |this, cx| {
                                        if (this.result_viewport_width - bounds.size.width).abs()
                                            >= px(1.)
                                        {
                                            this.result_viewport_width = bounds.size.width;
                                            cx.notify();
                                        }
                                    });
                                });
                            }),
                    ),
            )
            .into_any_element()
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
                if self.result_group() == Some(ArtifactGroup::Network) {
                    self.network.entries.len()
                } else {
                    self.index.ids.len()
                },
                if self.loading { " · searching" } else { "" }
            )))
            .when(self.result_group() == Some(ArtifactGroup::Memory), |toolbar| {
                let supported = self.selected.as_ref().is_some_and(|selected| {
                    self.case.as_ref().and_then(|case| {
                        let run = case.document.runs.iter().find(|r| r.id == selected.run_id)?;
                        volgui::memory_scan::Address::from_record(&run.plugin, &selected.record)
                    }).is_some()
                });
                toolbar.child(
                    app_button("view-scan-memory")
                        .small()
                        .label("View surrounding memory")
                        .disabled(!supported || self.loading || matches!(self.hex_view, HexView::Loading))
                        .tooltip(if supported {
                            "Open this result's bytes in the sidebar hex view. Collect process memory if needed."
                        } else {
                            "Select a result with a memory address to inspect"
                        })
                        .on_click(cx.listener(|this, _, _, cx| this.view_memory_scan(cx))),
                )
            })
            .child(
                div().w(px(260.)).child(
                    Input::new(&self.query)
                        .id("result-search")
                        .aria_label("Search artifacts")
                        .small()
                        .cleanable(true),
                ),
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
                RunStatus::Warning => {
                    "This analysis has incomplete coverage and returned no findings. See Run details for the warning and required changes.".into()
                }
            }
        } else if self.scope.is_empty() {
            format!("Run analyses to populate data: {}", self.scope_label)
        } else {
            "These analyses returned no results.".into()
        }
    }
}
