// Renders and manages the analysis configuration dialog.
use super::*;

impl Workspace {
    pub(in crate::ui) fn open_analysis_dialog(
        &mut self,
        targets: Vec<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.busy.is_some() {
            return;
        }
        self.analysis_drafts = self
            .case
            .as_ref()
            .map(|case| {
                targets
                    .iter()
                    .filter_map(|id| {
                        case.document
                            .evidence
                            .iter()
                            .find(|e| &e.id == id)
                            .map(AnalysisDraft::new)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if self.analysis_drafts.is_empty() {
            self.error = Some("Add evidence before choosing analyses".into());
            cx.notify();
            return;
        }
        self.analysis_active = 0;
        self.show_extended = false;
        self.allow_previous_plugins = false;
        self.analysis_collapsed_groups = ArtifactGroup::BROWSER
            .into_iter()
            .chain(ArtifactGroup::SHORTCUTS)
            .collect();
        self.analysis_error = None;
        self.analysis_group_filter = None;
        self.plugin = None;
        self.plugin_help.clear();
        self.plugin_query
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.arguments
            .update(cx, |s, cx| s.set_value("", window, cx));
        let workspace = cx.entity().downgrade();
        let panel = cx.new(|cx| AnalysisPanel {
            _subscription: cx.observe(&workspace.upgrade().unwrap(), |_, _, cx| cx.notify()),
            workspace: workspace.clone(),
        });
        let width = (window.viewport_size().width - px(64.)).min(px(1100.));
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .width(width)
                .overlay_closable(false)
                .child(panel.clone())
        });
        cx.notify();
    }
    pub(in crate::ui) fn render_plugins(
        &self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let Some(draft) = self.analysis_drafts.get(self.analysis_active) else {
            return div().into_any_element();
        };
        let total: usize = self.analysis_drafts.iter().map(|d| d.selected.len()).sum();
        let mut evidence = div().flex().gap_2().items_center().flex_wrap().child(
            div()
                .text_lg()
                .font_weight(FontWeight::SEMIBOLD)
                .child("Choose analyses"),
        );
        for (i, draft) in self.analysis_drafts.iter().enumerate() {
            let name = self
                .case
                .as_ref()
                .and_then(|c| {
                    c.document
                        .evidence
                        .iter()
                        .find(|e| e.id == draft.evidence_id)
                })
                .map_or_else(|| "Evidence".into(), |e| e.name());
            evidence = evidence.child(
                Button::new(key("analysis-evidence", &draft.evidence_id))
                    .small()
                    .label(name)
                    .selected(i == self.analysis_active)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_analysis_evidence(i, window, cx)
                    })),
            );
        }
        let mut os = div()
            .flex()
            .items_center()
            .gap_2()
            .child(heading("EVIDENCE OS", cx));
        for target in OperatingSystem::TARGETS {
            os = os.child(
                Button::new(key("os", target.label()))
                    .small()
                    .label(target.label())
                    .selected(target == draft.os)
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.set_os(target, window, cx)),
                    ),
            );
        }
        let height = (window.viewport_size().height - px(210.)).clamp(px(320.), px(590.));
        let mut page = div()
            .flex()
            .flex_col()
            .gap_3()
            .h(height)
            .min_h_0()
            .child(evidence)
            .child(os);
        let Some(engine) = &self.installation else {
            return page.child(div().text_sm().child("Configure Volatility to choose analyses. The evidence has already been added to the case."))
                .child(Button::new("analysis-settings").label("Configure Volatility").on_click(cx.listener(|this,_,window,cx| this.open_settings(window,cx))))
                .child(Button::new("analysis-later").label("Choose later").on_click(|_,window,cx| window.close_dialog(cx))).into_any_element();
        };
        let mut plugins = chooser_plugins(
            &volgui::analyses::application_plugins(&engine.plugins),
            draft.os,
            self.show_extended,
            self.plugin_query.read(cx).value().as_ref(),
        );
        if let Some(group) = self.analysis_group_filter {
            plugins.retain(|p| ArtifactGroup::for_plugin(&p.id) == group);
        }
        let previous: BTreeSet<String> = self
            .case
            .as_ref()
            .map(|case| {
                case.document
                    .runs
                    .iter()
                    .filter(|run| {
                        run.status.blocks_plugin_selection() && run.evidence_id == draft.evidence_id
                    })
                    .map(|run| run.plugin.clone())
                    .collect()
            })
            .unwrap_or_default();
        let allow_previous = self.allow_previous_plugins;
        let selectable = |id: &String| allow_previous || !previous.contains(id);
        let visible_ids: Vec<_> = plugins
            .iter()
            .map(|p| p.id.clone())
            .filter(&selectable)
            .collect();

        let basic_count = plugins
            .iter()
            .filter(|p| basic_label(&p.id).is_some())
            .count();
        page = page.child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    Input::new(&self.plugin_query)
                        .id("plugin-search")
                        .aria_label("Search analyses")
                        .small()
                        .cleanable(true)
                        .flex_1(),
                )
                .child(
                    Checkbox::new("show-extended")
                        .label("Show extended analyses")
                        .checked(self.show_extended)
                        .on_change(cx.listener(|this, value, _, cx| {
                            this.show_extended = *value;
                            cx.notify();
                        })),
                ),
        );
        page = page.child(
            Checkbox::new("allow-previous-plugins")
                .label("Allow previously run plugins")
                .checked(self.allow_previous_plugins)
                .on_change(cx.listener(|this, value, _, cx| {
                    this.allow_previous_plugins = *value;
                    if !*value && let Some(case) = &this.case {
                        for draft in &mut this.analysis_drafts {
                            draft.selected.retain(|id| {
                                !case.document.runs.iter().any(|run| {
                                    run.status.blocks_plugin_selection()
                                        && run.evidence_id == draft.evidence_id
                                        && &run.plugin == id
                                })
                            });
                        }
                    }
                    this.analysis_error = None;
                    cx.notify();
                })),
        );
        let selected = draft.selected.clone();
        let plugin_count = plugins.len();
        // Keep group headers and children in one virtualized list.
        let mut rows = Vec::new();
        let mut displayed_ids = Vec::new();
        let searching = !self.plugin_query.read(cx).value().trim().is_empty();
        for group in ArtifactGroup::BROWSER
            .into_iter()
            .chain(ArtifactGroup::SHORTCUTS)
        {
            let members: Vec<_> = plugins
                .iter()
                .enumerate()
                .filter(|(_, plugin)| {
                    basic_label(&plugin.id).is_some()
                        && ArtifactGroup::for_plugin(&plugin.id) == group
                })
                .collect();
            if members.is_empty() {
                continue;
            }
            if let [(index, plugin)] = members.as_slice() {
                if selectable(&plugin.id) {
                    displayed_ids.push(plugin.id.clone());
                }
                rows.push(Some((group, Some(*index), false, 1, 0)));
                continue;
            }
            let expanded = searching || !self.analysis_collapsed_groups.contains(&group);
            let count = members.len();
            let selected_count = members
                .iter()
                .filter(|(_, plugin)| selected.contains(&plugin.id))
                .count();
            rows.push(Some((group, None, expanded, count, selected_count)));
            if expanded {
                for (index, plugin) in members {
                    if selectable(&plugin.id) {
                        displayed_ids.push(plugin.id.clone());
                    }
                    rows.push(Some((group, Some(index), true, 0, 0)));
                }
            }
        }
        let extended: Vec<_> = plugins
            .iter()
            .enumerate()
            .filter(|(_, plugin)| basic_label(&plugin.id).is_none())
            .collect();
        if !extended.is_empty() {
            // A nonselectable section header separates the individual extended analyses.
            rows.push(None);
            for (index, plugin) in extended {
                if selectable(&plugin.id) {
                    displayed_ids.push(plugin.id.clone());
                }
                rows.push(Some((
                    ArtifactGroup::for_plugin(&plugin.id),
                    Some(index),
                    false,
                    1,
                    0,
                )));
            }
        }
        let rows = rows
            .into_iter()
            .map(|row| {
                use super::analysis_data_table::AnalysisRow;
                match row {
                    None => AnalysisRow::Extended,
                    Some((group, None, expanded, count, selected_count)) => {
                        let ids = plugins
                            .iter()
                            .filter(|plugin| {
                                basic_label(&plugin.id).is_some()
                                    && ArtifactGroup::for_plugin(&plugin.id) == group
                            })
                            .map(|plugin| plugin.id.clone())
                            .filter(&selectable)
                            .collect();
                        AnalysisRow::Group {
                            group,
                            expanded,
                            count,
                            selected_count,
                            ids,
                        }
                    }
                    Some((_, Some(index), _, count, _)) => {
                        let plugin = &plugins[index];
                        AnalysisRow::Plugin {
                            id: plugin.id.clone(),
                            description: plugin.description.clone(),
                            blocked: !selectable(&plugin.id),
                            previous: previous.contains(&plugin.id),
                            indented: count == 0,
                        }
                    }
                }
            })
            .collect();
        self.analysis_table.update(cx, |state, cx| {
            let delegate = state.delegate_mut();
            delegate.rows = rows;
            delegate.visible_ids = visible_ids;
            delegate.range_ids = std::rc::Rc::new(displayed_ids);
            cx.notify();
        });
        let table = div()
            .id("analysis-table")
            .w(px(772.))
            .max_w_full()
            .h_full()
            .min_h_0()
            .min_w_0()
            .child(
                DataTable::new(&self.analysis_table)
                    .small()
                    .header_row_height(px(32.)),
            );
        let mut body = div().flex().flex_1().min_h_0().gap_3().child(table);
        if let Some(id) = &self.plugin {
            body=body.child(div().flex().flex_col().gap_3().w(px(255.)).flex_shrink_0()
                .child(heading("PLUGIN OPTIONS",cx))
                .child(div().text_sm().child(id.clone()))
                .child(Input::new(&self.arguments).id("plugin-arguments").aria_label("Plugin arguments").small())
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Options are saved separately for each analysis. Select its checkbox to include it in the queue."))
                .child(Button::new("load-options").small().label("Load options").disabled(self.is_working()).on_click(cx.listener(|this,_,_,cx| this.plugin_help(cx))))
                .child(div().id("plugin-help").flex_1().min_h_0().overflow_y_scroll().text_xs().font_family("Consolas").child(self.plugin_help.clone())));
        }
        page.child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{basic_count} basic · {} extended · Shift-click checkboxes to select a range",
                    plugin_count - basic_count
                )),
        )
        .child(body)
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(div().flex_1().text_sm().child(format!(
                    "{total} analyses selected across {} evidence file(s)",
                    self.analysis_drafts.len()
                )))
                .child(
                    Button::new("cancel-analysis-selection")
                        .small()
                        .label("Choose later")
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                )
                .child(
                    Button::new("confirm-analyses")
                        .small()
                        .primary()
                        .label(format!("Queue {total} analyses"))
                        .disabled(total == 0 || self.busy.is_some())
                        .on_click(
                            cx.listener(|this, _, window, cx| this.queue_analyses(window, cx)),
                        ),
                ),
        )
        .into_any_element()
    }
}
struct AnalysisPanel {
    workspace: WeakEntity<Workspace>,
    _subscription: Subscription,
}
impl Render for AnalysisPanel {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.workspace
            .update(cx, |workspace, cx| workspace.render_plugins(window, cx))
            .unwrap_or_else(|_| div().into_any_element())
    }
}
