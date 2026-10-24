// Renders the window frame, navigation, and active view.
use super::*;

impl Render for Workspace {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.case.is_none() && !self.welcome_open {
            self.open_welcome(window, cx);
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
        let queued = self.case.as_ref().map_or(0, |c| {
            c.document
                .runs
                .iter()
                .filter(|r| r.status == RunStatus::Queued)
                .count()
        });
        let running = self.busy.as_ref().is_some_and(|b| b.run_id.is_some());
        let label = if running || queued > 0 {
            format!("{} running · {queued} queued", usize::from(running))
        } else {
            format!(
                "{} analyses · Ready",
                self.case
                    .as_ref()
                    .map_or(0, |c| c.document.queue_runs().count())
            )
        };
        let progress = if self.batch_total == 0 {
            0.
        } else {
            self.batch_finished as f32 / self.batch_total as f32 * 100.
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
                    .label("Hex")
                    .accessibility_label("Toggle hex view")
                    .selected(self.hex_visible)
                    .disabled(!case_open || self.view != View::Workspace)
                    .tooltip(if self.hex_visible {
                        "Hide hex view"
                    } else {
                        "Show hex view"
                    })
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_hex(cx))),
            )
            .when(
                self.busy.as_ref().is_some_and(|b| b.run_id.is_none()),
                |s| {
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
                },
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        ProgressCircle::new("queue-progress")
                            .xsmall()
                            .value(progress)
                            .loading(running && self.batch_finished == 0)
                            .accessibility_label("Finished analyses in current batch"),
                    )
                    .child(
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
                                    .label(label)
                                    .tooltip(
                                        self.busy
                                            .as_ref()
                                            .map(|b| b.label.clone())
                                            .unwrap_or_else(|| "Recent analyses and queue".into()),
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
                        Some(ArtifactGroup::Processes | ArtifactGroup::Files)
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
            .on_drag_move::<views::artifacts::ColumnResize>(
                cx.listener(|this, event, _, cx| this.resize_column(event, cx)),
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
            .when_some(self.error.clone(), |s, e| {
                s.child(
                    div()
                        .flex()
                        .items_start()
                        .px_4()
                        .py_2()
                        .gap_3()
                        .bg(rgb(0x321d25))
                        .child(
                            div()
                                .id("error-message")
                                .flex_1()
                                .max_h(px(70.))
                                .overflow_y_scroll()
                                .text_xs()
                                .child(e),
                        )
                        .child(
                            Button::new("dismiss-error")
                                .xsmall()
                                .ghost()
                                .label("Dismiss")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.error = None;
                                    cx.notify();
                                })),
                        ),
                )
            })
            .child(body)
            .child(status)
    }
}
