// Renders artifact pickers and the analysis queue.
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
    pub(super) fn artifact_plugins(&self, group: ArtifactGroup) -> Vec<volgui::volatility::Plugin> {
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
        let blocked = self.busy.is_some() || plugins.is_empty();
        div().w(px(440.)).p_3().flex().flex_col().gap_3()
            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(group.label()))
            .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Choose analyses to populate this artifact. Each checked analysis adds a separate job."))
            .when(plugins.is_empty(),|panel|panel.child(div().text_sm().child("No matching analyses in the configured installation. Check the evidence OS and engine settings.")))
            .child(list)
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
                this.analysis_group_filter=Some(group);this.show_extended=true;cx.notify();
            })))
            .into_any_element()
    }
    fn render_queue(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut runs = self
            .case
            .as_ref()
            .map(|case| {
                case.document
                    .queue_runs()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
            })
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
        let content_height = px(runs.len() as f32 * 32.);
        let list_height = content_height.clamp(px(32.), px(430.));
        let has_failed = runs
            .iter()
            .any(|run| matches!(run.status, RunStatus::Failed | RunStatus::Interrupted));
        let has_finished = runs
            .iter()
            .any(|run| QueueClearScope::Finished.includes(run.status));
        let mut list = div().id("queue-analyses").flex().flex_col().w_full().pr_3();
        if runs.is_empty() {
            list = list.child(
                div()
                    .h(px(32.))
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("No jobs in the queue"),
            );
        }
        for run in runs {
            let id = run.id.clone();
            let cancel = id.clone();
            let retry = id.clone();
            let remove = id.clone();
            let cancel_label = format!("Cancel {}", run.plugin);
            let active = matches!(run.status, RunStatus::Running | RunStatus::Queued);
            let color = match run.status {
                RunStatus::Running => Some(cx.theme().primary),
                RunStatus::Queued => Some(cx.theme().warning),
                RunStatus::Failed | RunStatus::Interrupted => Some(cx.theme().danger),
                RunStatus::Cancelled => Some(cx.theme().muted_foreground),
                _ => None,
            };
            let status = run.status.label();
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .h(px(32.))
                    .flex_shrink_0()
                    .when_some(color, |row, color| row.text_color(color))
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
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().min_w_0().text_sm().truncate().child(run.plugin))
                            .when(
                                !matches!(
                                    run.status,
                                    RunStatus::Failed
                                        | RunStatus::Cancelled
                                        | RunStatus::Interrupted
                                ),
                                |row| {
                                    row.child(
                                        div()
                                            .text_xs()
                                            .flex_shrink_0()
                                            .text_color(cx.theme().muted_foreground)
                                            .child(format!("{} records", run.row_count)),
                                    )
                                },
                            )
                            .child(div().flex_1())
                            .child(
                                div()
                                    .text_xs()
                                    .flex_shrink_0()
                                    .whitespace_nowrap()
                                    .text_color(color.unwrap_or(cx.theme().muted_foreground))
                                    .child(status),
                            )
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.queue_open = false;
                                this.select_run(id.clone(), window, cx);
                            })),
                    )
                    .when(
                        matches!(
                            run.status,
                            RunStatus::Failed | RunStatus::Interrupted | RunStatus::Cancelled
                        ),
                        |row| {
                            row.child(
                                Button::new(key("retry-queued-run", &retry))
                                    .xsmall()
                                    .ghost()
                                    .label("Retry")
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.retry_run(&retry, window, cx)
                                    })),
                            )
                        },
                    )
                    .when(!active, |row| {
                        row.child(
                            Button::new(key("remove-queued-run", &remove))
                                .accessibility_label("Remove finished analysis from queue")
                                .xsmall()
                                .ghost()
                                .icon(IconName::X)
                                .tooltip("Remove from queue")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.remove_queue_run(&remove, cx)
                                })),
                        )
                    })
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
            .child(
                div()
                    .relative()
                    .h(list_height)
                    .flex_shrink_0()
                    .child(
                        div()
                            .id("queue-scroll-viewport")
                            .size_full()
                            .overflow_y_scroll()
                            .track_scroll(&self.queue_scroll)
                            .child(list),
                    )
                    .child(Scrollbar::vertical(&self.queue_scroll).mode(ScrollbarMode::Always)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Button::new("queue-history")
                            .small()
                            .outline()
                            .label("History")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.queue_open = false;
                                this.navigate(View::Analyses, cx);
                            })),
                    )
                    .child(
                        Button::new("queue-retry-all-failed")
                            .small()
                            .outline()
                            .label("Retry all failed")
                            .tooltip("Retry all failed and interrupted analyses")
                            .disabled(!has_failed)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.retry_all_failed(window, cx);
                            })),
                    )
                    .child(
                        Button::new("queue-clear-finished")
                            .small()
                            .outline()
                            .label("Clear")
                            .tooltip("Clear completed, cancelled, failed and interrupted jobs from the queue. History and results are kept.")
                            .disabled(!has_finished)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.clear_queue(QueueClearScope::Finished, cx);
                            })),
                    ),
            )
            .into_any_element()
    }
}
