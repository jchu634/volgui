use super::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PanelKind {
    Queue,
    Artifact(ArtifactGroup),
}
pub(super) struct PopupPanel {
    workspace: WeakEntity<Workspace>,
    kind: PanelKind,
    _subscription: Subscription,
}
impl PopupPanel {
    pub(super) fn new(
        workspace: WeakEntity<Workspace>,
        kind: PanelKind,
        cx: &mut App,
    ) -> Entity<Self> {
        cx.new(|cx| Self {
            _subscription: cx.observe(&workspace.upgrade().unwrap(), |_, _, cx| cx.notify()),
            workspace,
            kind,
        })
    }
}
impl Render for PopupPanel {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.workspace
            .update(cx, |workspace, cx| match self.kind {
                PanelKind::Queue => workspace.render_queue(cx),
                PanelKind::Artifact(group) => workspace.render_artifact_picker(group, cx),
            })
            .unwrap_or_else(|_| div().into_any_element())
    }
}
impl Workspace {
    pub(super) fn popup_panel(
        &self,
        kind: PanelKind,
        cx: &mut Context<Self>,
    ) -> Entity<PopupPanel> {
        self.popup_panels
            .borrow_mut()
            .entry(kind)
            .or_insert_with(|| PopupPanel::new(cx.entity().downgrade(), kind, cx))
            .clone()
    }
    pub(super) fn artifact_plugins(
        &self,
        group: ArtifactGroup,
    ) -> Vec<volgui_again::volatility::Plugin> {
        let os = self
            .evidence()
            .map(|e| e.operating_system)
            .filter(|o| *o != OperatingSystem::Unknown)
            .unwrap_or(self.plugin_os);
        self.installation
            .as_ref()
            .map(|engine| {
                chooser_plugins(&engine.plugins, os, true, "")
                    .into_iter()
                    .filter(|p| ArtifactGroup::for_plugin(&p.id) == group)
                    .collect()
            })
            .unwrap_or_default()
    }
    pub(super) fn render_artifact_shortcut(
        &self,
        group: ArtifactGroup,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let available = !self.group_runs(group).is_empty();
        let label = if available {
            format!("{} · {}", group.label(), self.group_count(group))
        } else {
            group.label().into()
        };
        let panel = self.popup_panel(PanelKind::Artifact(group), cx);
        let dropdown = Popover::new(key("artifact-actions", group.label()))
            .anchor(Anchor::BottomLeft)
            .open(self.artifact_open == Some(group))
            .on_open_change(cx.listener(move |this, open, _, cx| {
                this.artifact_open = if *open { Some(group) } else { None };
                this.analysis_error = None;
                cx.notify();
            }))
            .trigger(
                Button::new(key("artifact-dropdown", group.label()))
                    .accessibility_label(format!("Related analyses for {}", group.label()))
                    .xsmall()
                    .ghost()
                    .icon(IconName::ChevronDown)
                    .tooltip("Related analyses"),
            )
            .content(move |_, _, _| panel.clone());
        div()
            .flex()
            .items_center()
            .w_full()
            .child(
                ActionButton::new(key("shortcut", group.label()))
                    .accessibility_label(format!("Open matching {} results", group.label()))
                    .h(px(30.))
                    .px_2()
                    .rounded_md()
                    .hover(|style| style.bg(cx.theme().muted))
                    .text_color(if available {
                        cx.theme().foreground
                    } else {
                        cx.theme().muted_foreground
                    })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_start()
                            .gap_2()
                            .w_full()
                            .child(Icon::new(Self::group_icon(group)).size_4())
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_xs()
                                    .text_left()
                                    .truncate()
                                    .child(label),
                            ),
                    )
                    .flex_1()
                    .min_w_0()
                    .justify_start()
                    .disabled(!available)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.artifact_open = None;
                        this.choose_group(group, window, cx);
                    })),
            )
            .child(dropdown)
            .into_any_element()
    }
    fn prepare_artifact_selection(&mut self, group: ArtifactGroup, all: bool) -> bool {
        let Some(evidence) = self.evidence() else {
            return false;
        };
        let mut draft = AnalysisDraft::new(evidence);
        draft.selected = if all {
            self.artifact_plugins(group)
                .into_iter()
                .map(|p| p.id)
                .collect()
        } else {
            self.artifact_choices
                .get(&group)
                .cloned()
                .unwrap_or_default()
        };
        self.analysis_drafts = vec![draft];
        self.analysis_active = 0;
        self.plugin = None;
        true
    }
    fn render_artifact_picker(&self, group: ArtifactGroup, cx: &mut Context<Self>) -> AnyElement {
        let plugins = self.artifact_plugins(group);
        let choices = self
            .artifact_choices
            .get(&group)
            .cloned()
            .unwrap_or_default();
        let count = choices.len();
        let mut list = div()
            .id("artifact-plugin-options")
            .flex()
            .flex_col()
            .gap_2()
            .max_h(px(280.))
            .overflow_y_scrollbar();
        for plugin in &plugins {
            let id = plugin.id.clone();
            list = list.child(
                Checkbox::new(key("artifact-plugin", &id))
                    .label(id.clone())
                    .checked(choices.contains(&id))
                    .on_change(cx.listener(move |this, checked, _, cx| {
                        let choices = this.artifact_choices.entry(group).or_default();
                        if *checked {
                            choices.insert(id.clone());
                        } else {
                            choices.remove(&id);
                        }
                        cx.notify();
                    })),
            );
        }
        let blocked = self.busy.as_ref().is_some_and(|b| b.run_id.is_none()) || plugins.is_empty();
        div().w(px(440.)).p_3().flex().flex_col().gap_3()
            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(group.label()))
            .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Choose analyses to populate this artifact. Each checked analysis adds a separate job."))
            .when(plugins.is_empty(),|panel|panel.child(div().text_sm().child("No matching analyses in the configured installation. Check the evidence OS and engine settings.")))
            .child(list)
            .when_some(self.analysis_error.clone(),|panel,error|panel.child(div().text_xs().text_color(cx.theme().danger).child(error)))
            .child(div().flex().gap_2()
                .child(Button::new("artifact-queue-selected").small().primary().label(format!("Queue selected ({count})")).disabled(blocked || count==0).on_click(cx.listener(move|this,_,window,cx|{
                    if this.prepare_artifact_selection(group,false) { this.queue_analyses(window,cx); if this.analysis_error.is_none(){this.artifact_open=None;} }
                })))
                .child(Button::new("artifact-queue-all").small().label(format!("Queue all ({})",plugins.len())).disabled(blocked).on_click(cx.listener(move|this,_,window,cx|{
                    if this.prepare_artifact_selection(group,true) {this.queue_analyses(window,cx);if this.analysis_error.is_none(){this.artifact_open=None;}}
                }))))
            .child(Button::new("artifact-review-options").small().ghost().label("Review selection and options...").disabled(blocked).on_click(cx.listener(move|this,_,window,cx|{
                let selected=this.artifact_choices.get(&group).cloned().unwrap_or_default();
                this.artifact_open=None;
                this.open_analysis_dialog(this.selected_evidence.iter().cloned().collect(),window,cx);
                if let Some(draft)=this.analysis_drafts.first_mut(){draft.selected=selected;}
                this.analysis_group_filter=Some(group);this.show_advanced=true;cx.notify();
            })))
            .into_any_element()
    }
    fn render_queue(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut runs = self
            .case
            .as_ref()
            .map(|case| case.document.runs.iter().rev().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        runs.sort_by_key(|run| match run.status {
            RunStatus::Running => 0,
            RunStatus::Queued => 1,
            _ => 2,
        });
        // Preserve execution order within the pending group.
        let pending_start = runs.iter().position(|r| r.status == RunStatus::Queued);
        if let Some(start) = pending_start {
            let end = runs[start..]
                .iter()
                .take_while(|r| r.status == RunStatus::Queued)
                .count()
                + start;
            runs[start..end].reverse();
        }
        let mut completed = 0;
        runs.retain(|run| {
            if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                true
            } else {
                completed += 1;
                completed <= 8
            }
        });
        let mut list = div()
            .id("queue-analyses")
            .max_h(px(430.))
            .flex()
            .flex_col()
            .overflow_y_scrollbar();
        for run in runs {
            let id = run.id.clone();
            let cancel = id.clone();
            let cancel_label = format!("Cancel {}", run.plugin);
            let active = matches!(run.status, RunStatus::Running | RunStatus::Queued);
            let status = if active {
                run.status.label().into()
            } else {
                format!("{} · {} records", run.status.label(), run.row_count)
            };
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .map(|row| if active { row.py_2() } else { row.py_1() })
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(
                        div()
                            .id(key("queue-run", &id))
                            .role(Role::Button)
                            .aria_label(format!("{} · {status}", run.plugin))
                            .flex_1()
                            .min_w_0()
                            .cursor_pointer()
                            .when(!active, |row| row.flex().items_center().gap_2())
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_sm()
                                    .truncate()
                                    .child(run.plugin),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .flex_shrink_0()
                                    .whitespace_nowrap()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(status),
                            )
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.queue_open = false;
                                this.select_run(id.clone(), window, cx);
                            })),
                    )
                    .when(active, |row| {
                        row.child(
                            Button::new(key("cancel-queued-run", &cancel))
                                .accessibility_label(cancel_label)
                                .xsmall()
                                .ghost()
                                .icon(IconName::X)
                                .tooltip("Cancel analysis")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.cancel_run(cancel.clone(), cx)
                                })),
                        )
                    }),
            );
        }
        div()
            .w(px(400.))
            .p_3()
            .flex()
            .flex_col()
            .gap_2()
            .child(heading("ANALYSIS QUEUE", cx))
            .child(list)
            .child(
                Button::new("queue-history")
                    .small()
                    .ghost()
                    .label("Analysis history...")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.queue_open = false;
                        this.navigate(View::Analyses, cx);
                    })),
            )
            .into_any_element()
    }
}
