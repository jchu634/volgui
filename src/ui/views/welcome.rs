// Requires case selection or creation in the welcome dialog.
use super::*;
use crate::ui::chrome::FileCommand;

impl Workspace {
    pub(in crate::ui) fn render_welcome(&self, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex_1()
            .p_8()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_2xl().child("No case open"))
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Create a case or continue an investigation."),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        app_button("welcome-new-case")
                            .primary()
                            .label("New case")
                            .disabled(!self.can_switch())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.navigate(View::NewCase, cx);
                            })),
                    )
                    .child(
                        app_button("welcome-open-case")
                            .label("Open case")
                            .disabled(!self.can_switch())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_path("open", window, cx)
                            })),
                    )
                    .child(
                        app_button("welcome-recent-cases")
                            .label("Open recent case")
                            .disabled(!self.can_switch() || self.settings.recent_cases.is_empty())
                            .dropdown_caret(true)
                            .dropdown_menu({
                                let recent = self.settings.recent_cases.clone();
                                let weak = cx.entity().downgrade();
                                move |mut menu, _, _| {
                                    for path in &recent {
                                        menu = menu.item(Self::file_item(
                                            path.parent()
                                                .unwrap_or(path)
                                                .file_name()
                                                .unwrap_or_default()
                                                .to_string_lossy()
                                                .into_owned(),
                                            FileCommand::Recent(path.clone()),
                                            false,
                                            weak.clone(),
                                        ));
                                    }
                                    menu
                                }
                            }),
                    ),
            )
            .when(self.installation.is_none(), |s| {
                s.child(
                    app_button("configure-engine")
                        .small()
                        .label("Configure analysis engine")
                        .on_click(
                            cx.listener(|this, _, window, cx| this.open_settings(window, cx)),
                        ),
                )
            })
            .into_any_element()
    }
}

struct WelcomePanel {
    workspace: WeakEntity<Workspace>,
    _subscription: Subscription,
}
impl Render for WelcomePanel {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.workspace
            .update(cx, |workspace, cx| {
                div()
                    .flex()
                    .flex_col()
                    .child(if workspace.view == View::NewCase {
                        workspace.render_new_case(cx)
                    } else {
                        workspace.render_welcome(cx)
                    })
                    .when(workspace.view == View::NewCase, |s| {
                        s.child(
                            app_button("welcome-back")
                                .label("Back")
                                .disabled(!workspace.can_switch())
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.navigate(View::Workspace, cx);
                                })),
                        )
                    })
                    .into_any_element()
            })
            .unwrap_or_else(|_| div().into_any_element())
    }
}
impl Workspace {
    pub(in crate::ui) fn open_welcome(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.welcome_open = true;
        let workspace = cx.entity().downgrade();
        let panel = cx.new(|cx| WelcomePanel {
            _subscription: cx.observe(&workspace.upgrade().unwrap(), |_, _, cx| cx.notify()),
            workspace,
        });
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .width(px(760.))
                .close_button(false)
                .overlay_closable(false)
                .keyboard(false)
                .on_cancel(|_, _, _| false)
                .child(panel.clone())
        });
    }
}
