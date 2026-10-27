// Renders the window frame, navigation, and active view.
use super::*;

fn titlebar_logo() -> Arc<Image> {
    static LOGO: std::sync::OnceLock<Arc<Image>> = std::sync::OnceLock::new();
    LOGO.get_or_init(|| {
        Arc::new(Image::from_bytes(
            ImageFormat::Png,
            // Original PNG embedded in logo_dark.svg, preserved without recoloring.
            include_bytes!("../../assets/logo-dark.png").to_vec(),
        ))
    })
    .clone()
}

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
                .child(img(titlebar_logo()).size_5().flex_shrink_0())
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
                            app_button("navigate-back")
                                .ghost()
                                .accessibility_label("Back")
                                .xsmall()
                                .icon(IconName::ArrowLeft)
                                .tooltip("Back")
                                .disabled(self.back_stack.is_empty())
                                .on_click(
                                    cx.listener(|this, _, window, cx| this.go_back(window, cx)),
                                ),
                        )
                        .child(
                            app_button("file-menu")
                                .ghost()
                                .xsmall()
                                .label("File")
                                .dropdown_caret(true)
                                .dropdown_menu(move |menu, window, cx| {
                                    Self::file_menu(file_weak.clone(), menu, window, cx)
                                }),
                        )
                        .child(
                            app_button("view-menu")
                                .ghost()
                                .xsmall()
                                .label("View")
                                .dropdown_caret(true)
                                .dropdown_menu(move |menu, _, cx| {
                                    Self::view_menu(view_weak.clone(), menu, cx)
                                }),
                        ),
                )
                .when_some(self.case.as_ref(), |bar, case| {
                    bar.child(div().h_4().w_px().bg(cx.theme().border)).child(
                        div()
                            .min_w_0()
                            .truncate()
                            .text_sm()
                            .child(case.document.name.clone()),
                    )
                })
                .child(div().flex_1())
                .child(
                    div()
                        .mr_2()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .child(
                            app_button("new-analysis")
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
        self.restore_result_scroll(cx);
        let content = if self.sidebar_visible && case_open {
            h_resizable("workspace-sidebar-split")
                .child(
                    resizable_panel()
                        .size(px(282.))
                        .size_range(px(220.)..px(560.))
                        .fixed()
                        .child(self.render_sidebar(cx)),
                )
                .child(
                    resizable_panel()
                        .size_range(px(320.)..Pixels::MAX)
                        .child(content),
                )
                .into_any_element()
        } else {
            content
        };
        let body = div().flex().flex_1().min_h_0().min_w_0().child(content);
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
                app_button("toggle-sidebar")
                    .ghost()
                    .xsmall()
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
            .when(self.busy.is_some(), |s| {
                s.child(
                    app_button("cancel-work")
                        .ghost()
                        .xsmall()
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
                            app_button("queue-indicator")
                                .ghost()
                                .xsmall()
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
            )
            .child(
                app_button("toggle-content-sidebar")
                    .ghost()
                    .xsmall()
                    .icon(IconName::PanelRight)
                    .accessibility_label("Toggle supplemental sidebar")
                    .selected(self.content_sidebar_visible)
                    .disabled(!case_open || !self.supports_content_sidebar())
                    .tooltip(if self.content_sidebar_visible {
                        "Hide sidebar"
                    } else {
                        "Show sidebar"
                    })
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_content_sidebar(cx))),
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
                                | ArtifactGroup::Modules
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
            .when(cfg!(target_os = "windows"), |s| {
                s.child(self.render_window_controls(window, cx))
            })
            .child(body)
            .child(status)
    }
}
