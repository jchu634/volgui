// Renders and manages the analysis configuration dialog.
use super::*;

impl Workspace {
    pub(in crate::ui) fn open_analysis_dialog(
        &mut self,
        targets: Vec<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.busy.as_ref().is_some_and(|b| b.run_id.is_none()) {
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
        self.show_advanced = false;
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
                .title("Choose analyses")
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
        let mut evidence = div().flex().gap_2().items_center().flex_wrap();
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
                    .label(format!("{name} · {} selected", draft.selected.len()))
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
            &engine.plugins,
            draft.os,
            self.show_advanced,
            self.plugin_query.read(cx).value().as_ref(),
        );
        if let Some(group) = self.analysis_group_filter {
            plugins.retain(|p| ArtifactGroup::for_plugin(&p.id) == group);
        }
        let visible_ids: Vec<_> = plugins.iter().map(|p| p.id.clone()).collect();
        let range_ids = Rc::new(visible_ids.clone());
        let all_visible_selected =
            !visible_ids.is_empty() && visible_ids.iter().all(|id| draft.selected.contains(id));
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
                    Checkbox::new("show-advanced")
                        .label("Show advanced analyses")
                        .checked(self.show_advanced)
                        .on_change(cx.listener(|this, value, _, cx| {
                            this.show_advanced = *value;
                            cx.notify();
                        })),
                ),
        );
        let selected = draft.selected.clone();
        let focused = self.plugin.clone();
        let header = div()
            .id("analysis-table-header")
            .flex()
            .items_center()
            .h(px(34.))
            .gap_2()
            .px_2()
            .bg(cx.theme().muted)
            .role(Role::Row)
            .child(
                div().w(px(24.)).child(
                    Checkbox::new("select-visible-analyses")
                        .accessibility_label("Select all visible analyses")
                        .checked(all_visible_selected)
                        .disabled(visible_ids.is_empty())
                        .on_change(cx.listener(move |this, value, _, cx| {
                            if let Some(draft) = this.analysis_drafts.get_mut(this.analysis_active)
                            {
                                for id in &visible_ids {
                                    if *value {
                                        draft.selected.insert(id.clone());
                                    } else {
                                        draft.selected.remove(id);
                                    }
                                }
                            }
                            cx.notify();
                        })),
                ),
            )
            .child(
                div()
                    .id("analysis-name-header")
                    .flex_1()
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Analysis"),
            )
            .child(
                div()
                    .id("analysis-plugin-header")
                    .flex_1()
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Plugin"),
            )
            .child(
                div()
                    .id("analysis-level-header")
                    .w(px(70.))
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Level"),
            )
            .child(
                div()
                    .id("analysis-options-header")
                    .w(px(58.))
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Options"),
            );
        let len = plugins.len();
        let list = uniform_list(
            "analysis-table-rows",
            len,
            cx.processor(move |_, range: Range<usize>, _, cx| {
                range
                    .map(|i| {
                        let plugin = &plugins[i];
                        let id = plugin.id.clone();
                        let check_id = id.clone();
                        let range_ids = range_ids.clone();
                        let options_id = id.clone();
                        let label = basic_label(&id)
                            .map(str::to_owned)
                            .unwrap_or_else(|| id.rsplit('.').next().unwrap_or(&id).to_string());
                        let basic = basic_label(&id).is_some();
                        let description = plugin.description.clone();
                        div()
                            .id(key("analysis-row", &id))
                            .role(Role::Row)
                            .w_full()
                            .h(px(38.))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_2()
                            .border_b_1()
                            .border_color(cx.theme().border)
                            .when(focused.as_ref() == Some(&id), |row| {
                                row.bg(cx.theme().accent)
                            })
                            .child(
                                div().w(px(24.)).child(
                                    Checkbox::new(key("select-analysis", &id))
                                        .accessibility_label(format!("Select {id}"))
                                        .checked(selected.contains(&id))
                                        .on_change(cx.listener(move |this, value, window, cx| {
                                            if let Some(draft) =
                                                this.analysis_drafts.get_mut(this.analysis_active)
                                            {
                                                draft.select(
                                                    &check_id,
                                                    *value,
                                                    window.modifiers().shift,
                                                    &range_ids,
                                                );
                                            }
                                            this.analysis_error = None;
                                            cx.notify();
                                        })),
                                ),
                            )
                            .child(
                                div()
                                    .id(key("analysis-label", &id))
                                    .flex_1()
                                    .min_w_0()
                                    .text_sm()
                                    .truncate()
                                    .child(label)
                                    .tooltip(move |window, cx| {
                                        Tooltip::new(description.clone()).build(window, cx)
                                    }),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .truncate()
                                    .child(id.clone()),
                            )
                            .child(
                                div()
                                    .w(px(70.))
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(if basic { "Basic" } else { "Advanced" }),
                            )
                            .child(
                                Button::new(key("analysis-options", &id))
                                    .xsmall()
                                    .ghost()
                                    .label("Options")
                                    .w(px(58.))
                                    .tooltip(format!("Options for {id}"))
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.focus_plugin(options_id.clone(), window, cx)
                                    })),
                            )
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .flex_1()
        .w_full()
        .min_h_0();
        let table = div()
            .id("analysis-table")
            .role(Role::Table)
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .border_1()
            .border_color(cx.theme().border)
            .child(header)
            .when(len == 0, |s| {
                s.child(div().p_4().text_sm().child(
                    "No matching analyses. Try showing advanced analyses or changing the search.",
                ))
            })
            .child(list);
        let mut body = div().flex().flex_1().min_h_0().gap_3().child(table);
        if let Some(id) = &self.plugin {
            body=body.child(div().flex().flex_col().gap_3().w(px(255.)).flex_shrink_0()
                .child(heading("PLUGIN OPTIONS",cx))
                .child(div().text_sm().child(id.clone()))
                .child(Input::new(&self.arguments).id("plugin-arguments").aria_label("Plugin arguments").small())
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Options are saved separately for each analysis. Select its checkbox to include it in the queue."))
                .child(Button::new("load-options").small().label("Load options").disabled(self.busy.is_some()).on_click(cx.listener(|this,_,_,cx| this.plugin_help(cx))))
                .child(div().id("plugin-help").flex_1().min_h_0().overflow_y_scroll().text_xs().font_family("Consolas").child(self.plugin_help.clone())));
        }
        page.child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{basic_count} basic · {} advanced · Shift-click checkboxes to select a range",
                    len - basic_count
                )),
        )
        .child(body)
        .when_some(self.analysis_error.clone(), |s, error| {
            s.child(div().text_sm().text_color(cx.theme().danger).child(error))
        })
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
                        .disabled(
                            total == 0 || self.busy.as_ref().is_some_and(|b| b.run_id.is_none()),
                        )
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
