// Renders analysis run history.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_analyses(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("analyses")
            .flex_1()
            .overflow_y_scrollbar()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().text_xl().child("Analysis history"));
        let Some(case) = &self.case else {
            return page.into_any_element();
        };
        if self.queue_paused {
            page = page.child(
                Button::new("resume-queue")
                    .label("Retry save and resume queue")
                    .on_click(cx.listener(|this, _, _, cx| {
                        match this.case.as_mut().unwrap().save() {
                            Ok(()) => this.queue_paused = false,
                            Err(e) => this.error = Some(e),
                        }
                        cx.notify();
                    })),
            );
        }
        for run in case.document.runs.iter().rev() {
            let id = run.id.clone();
            let cancel = id.clone();
            let rerun = id.clone();
            let mut actions = div().flex().flex_col().gap_1().child(
                Button::new(key("inspect", &id))
                    .small()
                    .label("Inspect")
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_run(id.clone(), window, cx)
                    })),
            );
            if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                actions = actions.child(
                    Button::new(key("cancel", &cancel))
                        .small()
                        .label("Cancel")
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.cancel_run(cancel.clone(), cx)),
                        ),
                );
            } else {
                actions = actions.child(
                    Button::new(key("rerun", &rerun))
                        .small()
                        .label("Rerun setup")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(run) = this
                                .case
                                .as_ref()
                                .and_then(|c| c.document.runs.iter().find(|r| r.id == rerun))
                                .cloned()
                            {
                                let target = run.evidence_id.clone();
                                this.open_analysis_dialog(vec![target], window, cx);
                                if let Some(draft) = this.analysis_drafts.first_mut() {
                                    draft.selected.insert(run.plugin.clone());
                                    draft.arguments.insert(
                                        run.plugin.clone(),
                                        format_arguments(&run.arguments),
                                    );
                                }
                                this.allow_previous_plugins = true;
                                this.show_extended = basic_label(&run.plugin).is_none();
                                this.focus_plugin(run.plugin, window, cx);
                            }
                        })),
                );
            }
            if matches!(run.status, RunStatus::Failed | RunStatus::Interrupted) {
                let retry = run.id.clone();
                actions = actions.child(
                    Button::new(key("retry-analysis", &retry))
                        .small()
                        .label("Retry")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.retry_run(&retry, window, cx)
                        })),
                );
            }
            let summary = if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                run.status.label().to_string()
            } else {
                format!("{} · {} records", run.status.label(), run.row_count)
            };
            page = page.child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .p_3()
                    .border_1()
                    .border_color(cx.theme().border)
                    .rounded_md()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .truncate()
                                    .when(run.status == RunStatus::Cancelled, |text| {
                                        text.text_color(cx.theme().muted_foreground)
                                    })
                                    .child(run.plugin.clone()),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(summary)
                                    .child(run.created_at.clone()),
                            )
                            .when(run.status == RunStatus::Failed, |text| {
                                text.child(
                                    div()
                                        .text_xs()
                                        .child(run.message.chars().take(500).collect::<String>()),
                                )
                            }),
                    )
                    .child(actions),
            );
        }
        page.into_any_element()
    }
}
