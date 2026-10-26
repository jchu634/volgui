// Renders the case creation form.
use std::path::Path;

use super::*;

impl Workspace {
    pub(in crate::ui) fn render_new_case(&self, cx: &mut Context<Self>) -> AnyElement {
        let parent = self.case_directory.read(cx).value().trim().to_string();
        let name = self.case_name.read(cx).value().trim().to_string();
        let location = (!parent.is_empty() && !name.is_empty())
            .then(|| Path::new(&parent).join(&name).display().to_string());
        div()
            .flex_1()
            .p_6()
            .child(
                div()
                    .max_w(px(720.))
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(div().text_2xl().child("New case"))
                    .child(heading("Case name", cx))
                    .child(
                        Input::new(&self.case_name)
                            .id("case-name")
                            .aria_label("Case name"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("A new folder with this name will hold the case."),
                    )
                    .child(heading("Location", cx))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Input::new(&self.case_directory)
                                    .id("case-directory")
                                    .aria_label("Folder to create the case in")
                                    .flex_1(),
                            )
                            .child(app_button("browse-case").label("Browse").on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.choose_path("directory", window, cx)
                                }),
                            )),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("The case is created in a new folder inside this location."),
                    )
                    .when_some(location, |form, location| {
                        form.child(
                            div()
                                .text_sm()
                                .flex()
                                .gap_1()
                                .child("The case will be created at")
                                .child(div().font_weight(FontWeight::SEMIBOLD).child(location)),
                        )
                    })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                app_button("create-case")
                                    .primary()
                                    .w(px(150.))
                                    .label("Create case")
                                    .disabled(!self.can_switch())
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.create_case(window, cx)
                                    })),
                            )
                            .when(self.welcome_open, |row| {
                                row.child(
                                    app_button("welcome-back")
                                        .label("Back")
                                        .disabled(!self.can_switch())
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.navigate(View::Workspace, cx);
                                        })),
                                )
                            }),
                    ),
            )
            .into_any_element()
    }
}
