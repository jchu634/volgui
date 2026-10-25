// Renders the case creation form.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_new_case(&self, cx: &mut Context<Self>) -> AnyElement {
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
                    .child(heading("Name", cx))
                    .child(
                        Input::new(&self.case_name)
                            .id("case-name")
                            .aria_label("Case name"),
                    )
                    .child(heading("Directory", cx))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Input::new(&self.case_directory)
                                    .id("case-directory")
                                    .aria_label("Case directory")
                                    .flex_1(),
                            )
                            .child(Button::new("browse-case").label("Browse").on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.choose_path("directory", window, cx)
                                }),
                            )),
                    )
                    .child(
                        Button::new("create-case")
                            .primary()
                            .w(px(150.))
                            .label("Create case")
                            .disabled(!self.can_switch())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.create_case(window, cx)),
                            ),
                    ),
            )
            .into_any_element()
    }
}
