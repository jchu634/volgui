// Renders the window frame, navigation, and active view.
use super::*;

impl Render for Workspace {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.case.is_none() && !self.welcome_open {
            self.open_welcome(window, cx);
        }
        // Defer notification updates until after the workspace finishes rendering.
        // Taking the errors prevents unrelated redraws from repeating a toast.
        for error in [self.error.take(), self.analysis_error.take()]
            .into_iter()
            .flatten()
        {
            window.defer(cx, move |window, cx| {
                window.push_notification(Notification::error(error), cx);
            });
        }
        let file_weak = cx.entity().downgrade();
        let view_weak = cx.entity().downgrade();
        let case_open = self.case.is_some();
        let title = TitleBar::new().child(
            div()
                .flex()
                .flex_1()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .text_color(rgb(0xd96b87))
                        .child(Icon::new(IconName::Shield).size_4()),
                )
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("volgui"),
                )
                .child(div().h_4().w_px().bg(cx.theme().border))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .child(
                            Button::new("navigate-back")
                                .accessibility_label("Back")
                                .xsmall()
                                .ghost()
                                .icon(IconName::ArrowLeft)
                                .tooltip("Back")
                                .disabled(self.back_stack.is_empty())
                                .on_click(
                                    cx.listener(|this, _, window, cx| this.go_back(window, cx)),
                                ),
                        )
                        .child(
                            Button::new("file-menu")
                                .ghost()
                                .xsmall()
                                .label("File")
                                .dropdown_caret(true)
                                .dropdown_menu(move |menu, window, cx| {
                                    Self::file_menu(file_weak.clone(), menu, window, cx)
                                }),
                        )
                        .child(
                            Button::new("view-menu")
                                .ghost()
                                .xsmall()
                                .label("View")
                                .dropdown_caret(true)
                                .dropdown_menu(move |menu, _, cx| {
                                    Self::view_menu(view_weak.clone(), menu, cx)
                                }),
                        ),
                )
                .child(div().flex_1())
                .child(
                    div()
                        .mr_2()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .child(
                            Button::new("new-analysis")
                                .xsmall()
                                .primary()
                                .icon(IconName::Plus)
                                .label("New analysis")
                                .disabled(!case_open)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.open_analysis_dialog(
                                        this.selected_evidence.iter().cloned().collect(),
                                        window,
                                        cx,
                                    );
                                })),
                        ),
                ),
        );
        let content = if !case_open {
            div().into_any_element()
        } else {
            match self.view {
                View::NewCase => self.render_new_case(cx),
                View::Workspace => self.render_workspace(cx),
                View::Analyses => self.render_analyses(cx),
                View::Bookmarks => self.render_bookmarks(cx),
                View::CaseInfo => self.render_case_info(cx),
            }
        };
        let body = div()
            .flex()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .when(self.sidebar_visible && case_open, |s| {
                s.child(self.render_sidebar(cx))
            })
            .child(content);
        let runs: Vec<_> = self
            .case
            .as_ref()
            .map(|case| case.document.queue_runs().collect())
            .unwrap_or_default();
        let total = runs.len();
        let finished = runs
            .iter()
            .filter(|run| !matches!(run.status, RunStatus::Running | RunStatus::Queued))
            .count();
        let failed = runs.iter().any(|run| {
            matches!(
                run.status,
                RunStatus::Failed | RunStatus::Interrupted | RunStatus::Cancelled
            )
        });
        let label = format!("{finished}/{total}");
        let progress = if total == 0 {
            0.
        } else {
            finished as f32 / total as f32 * 100.
        };
        let progress_color = if total > 0 && finished == total {
            if failed {
                cx.theme().danger
            } else {
                cx.theme().success
            }
        } else {
            rgb(0xffffff).into()
        };
        let queue_panel = self.popup_panel(popups::PanelKind::Queue, cx);
        let status = div()
            .flex()
            .flex_shrink_0()
            .h(px(38.))
            .items_center()
            .px_3()
            .gap_3()
            .border_t_1()
            .border_color(cx.theme().border)
            .child(
                Button::new("toggle-sidebar")
                    .xsmall()
                    .ghost()
                    .icon(IconName::PanelLeft)
                    .accessibility_label("Toggle evidence sidebar")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.sidebar_visible = !this.sidebar_visible;
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_xs()
                    .truncate()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.message.clone()),
            )
            .child(
                Button::new("toggle-hex-view")
                    .xsmall()
                    .ghost()
                    .label("Contents")
                    .accessibility_label("Toggle file contents")
                    .selected(self.hex_visible)
                    .disabled(!case_open || self.view != View::Workspace)
                    .tooltip(if self.hex_visible {
                        "Hide hex view"
                    } else {
                        "Show hex view"
                    })
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_hex(cx))),
            )
            .when(self.busy.is_some(), |s| {
                s.child(
                    Button::new("cancel-work")
                        .xsmall()
                        .ghost()
                        .label("Cancel")
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let Some(b) = &this.busy {
                                b.cancel.store(true, Ordering::Relaxed);
                            }
                            cx.notify();
                        })),
                )
            })
            .child(
                div().flex().items_center().gap_2().child(
                    Popover::new("queue-popover")
                        .anchor(Anchor::BottomRight)
                        .open(self.queue_open)
                        .on_open_change(cx.listener(|this, open, _, cx| {
                            this.queue_open = *open;
                            cx.notify();
                        }))
                        .trigger(
                            Button::new("queue-indicator")
                                .xsmall()
                                .ghost()
                                .child(
                                    ProgressCircle::new("queue-progress")
                                        .xsmall()
                                        .value(progress)
                                        .color(progress_color)
                                        .accessibility_label(
                                            "Finished analyses out of total analyses",
                                        ),
                                )
                                .child(label)
                                .tooltip(
                                    self.busy.as_ref().map(|b| b.label.clone()).unwrap_or_else(
                                        || {
                                            format!(
                                                "{} running / {} maximum",
                                                self.running.len(),
                                                self.settings.max_concurrent_jobs
                                            )
                                        },
                                    ),
                                )
                                .dropdown_caret(true),
                        )
                        .content(move |_, _, _| queue_panel.clone()),
                ),
            );
        div()
            .id("workspace-root")
            .track_focus(&self.workspace_focus)
            .on_key_down(cx.listener(|this, event, window, cx| {
                if this.workspace_focus.is_focused(window)
                    && this.view == View::Workspace
                    && matches!(
                        this.result_group(),
                        Some(
                            ArtifactGroup::Processes
                                | ArtifactGroup::Files
                                | ArtifactGroup::Registry
                        )
                    )
                {
                    this.tree_key_down(event, cx);
                }
            }))
            .on_action(
                cx.listener(|_, _: &gpui_kit::base::input::Copy, window, cx| {
                    let text = gpui_kit::base::TextSelection::selected_text(window, cx);
                    if text.is_empty() {
                        cx.propagate();
                    } else {
                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                    }
                }),
            )
            .flex()
            .flex_col()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(title)
            .when(self.welcome_open && cfg!(target_os = "windows"), |s| {
                s.child(self.render_modal_window_controls(window, cx))
            })
            .child(body)
            .child(status)
    }
}
