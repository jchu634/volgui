// Renders artifact results and record details.
use super::*;

impl Workspace {
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
        let results = if self.content_sidebar_visible {
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
            Some(ArtifactGroup::Registry) => {
                return self.render_artifact_tree(ArtifactGroup::Registry, cx);
            }
            _ => {}
        }
        self.sync_result_table(cx);
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
                    .aria_label("Artifact results")
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(
                        DataTable::new(&self.result_table)
                            .small()
                            .header_row_height(px(32.)),
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
