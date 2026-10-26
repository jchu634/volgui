// Renders artifact navigation and the analysis queue.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PanelKind {
    Queue,
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
    pub(super) fn render_artifact_shortcut(
        &self,
        group: ArtifactGroup,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        app_button(key("shortcut", group.label()))
            .self_start()
            .w_full()
            .ghost()
            .small()
            .accessibility_label(group.label())
            .selected(self.view == View::Workspace && self.result_group() == Some(group))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .w_full()
                    .child(Icon::new(Self::group_icon(group)).size_4())
                    .child(group.label()),
            )
            .on_click(cx.listener(move |this, _, window, cx| this.choose_group(group, window, cx)))
            .into_any_element()
    }
    fn render_queue(&self, cx: &mut Context<Self>) -> AnyElement {
        // Keep only display data; a run can contain large arguments and diagnostics.
        struct QueueRow {
            id: String,
            plugin: String,
            status: RunStatus,
            row_count: usize,
        }
        let mut runs = self
            .case
            .as_ref()
            .map(|case| {
                case.document
                    .queue_runs()
                    .rev()
                    .map(|run| QueueRow {
                        id: run.id.clone(),
                        plugin: run.plugin.clone(),
                        status: run.status,
                        row_count: run.row_count,
                    })
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
        let list = if runs.is_empty() {
            div()
                .h(px(32.))
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child("No jobs in the queue")
                .into_any_element()
        } else {
            uniform_list(
                "queue-analyses",
                runs.len(),
                cx.processor(move |_, range: Range<usize>, _, cx| {
                    range
                        .map(|index| {
                            let run = &runs[index];
                            let id = run.id.clone();
                            let cancel = id.clone();
                            let retry = id.clone();
                            let remove = id.clone();
                            let cancel_label = format!("Cancel {}", run.plugin);
                            let active =
                                matches!(run.status, RunStatus::Running | RunStatus::Queued);
                            let color = match run.status {
                                RunStatus::Running => Some(cx.theme().primary),
                                RunStatus::Queued => Some(cx.theme().warning),
                                RunStatus::Failed | RunStatus::Interrupted => {
                                    Some(cx.theme().danger)
                                }
                                RunStatus::Cancelled => Some(cx.theme().muted_foreground),
                                _ => None,
                            };
                            let status = run.status.label();
                            div()
                                .flex()
                                .w_full()
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
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .text_sm()
                                                .truncate()
                                                .child(run.plugin.clone()),
                                        )
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
                                                        .child(format!(
                                                            "{} records",
                                                            run.row_count
                                                        )),
                                                )
                                            },
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .flex_shrink_0()
                                                .whitespace_nowrap()
                                                .text_color(
                                                    color.unwrap_or(cx.theme().muted_foreground),
                                                )
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
                                        RunStatus::Failed
                                            | RunStatus::Interrupted
                                            | RunStatus::Cancelled
                                    ),
                                    |row| {
                                        row.child(
                                            app_button(key("retry-queued-run", &retry))
                                                .xsmall()
                                                .label("Retry")
                                                .on_click(cx.listener(
                                                    move |this, _, window, cx| {
                                                        this.retry_run(&retry, window, cx)
                                                    },
                                                )),
                                        )
                                    },
                                )
                                .when(!active, |row| {
                                    row.child(
                                        app_button(key("remove-queued-run", &remove))
                                            .ghost()
                                            .accessibility_label(
                                                "Remove finished analysis from queue",
                                            )
                                            .xsmall()
                                            .icon(IconName::X)
                                            .tooltip("Remove from queue")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.remove_queue_run(&remove, cx)
                                            })),
                                    )
                                })
                                .when(active, |row| {
                                    row.child(
                                        app_button(key("cancel-queued-run", &cancel))
                                            .ghost()
                                            .accessibility_label(cancel_label)
                                            .xsmall()
                                            .icon(IconName::X)
                                            .tooltip("Cancel analysis")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.cancel_run(cancel.clone(), cx)
                                            })),
                                    )
                                })
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(&self.queue_scroll)
            .size_full()
            .pr_3()
            .into_any_element()
        };
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
                    .child(list)
                    .child(Scrollbar::vertical(&self.queue_scroll).mode(ScrollbarMode::Always)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        app_button("queue-history")
                            .small()
                            .outline()
                            .label("History")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.queue_open = false;
                                this.navigate(View::Analyses, cx);
                            })),
                    )
                    .child(
                        app_button("queue-retry-all-failed")
                            .small()
                            .outline()
                            .label("Retry all failed")
                            .tooltip("Retry all failed and interrupted analyses")
                            .disabled(!has_failed)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.retry_all_failed(window, cx);
                            })),
                    )
                    .child(div().flex_1())
                    .child(
                        app_button("queue-clear-failed")
                            .small()
                            .outline()
                            .label("Clear failed")
                            .tooltip("Clear failed and interrupted jobs from the queue. History and results are kept.")
                            .disabled(!has_failed)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.clear_queue(QueueClearScope::Failed, cx);
                            })),
                    )
                    .child(
                        app_button("queue-clear-finished")
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
