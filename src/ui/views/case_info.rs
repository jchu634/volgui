// Renders case metadata and evidence verification.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_case_info(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_xl().child("Case information"));
        if let Some(case) = &self.case {
            page = page.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(div().text_sm().child(case.document.name.clone()))
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .flex_1()
                            .min_w_0()
                            .child(case.directory.display().to_string()),
                    )
                    .child(
                        app_button("export-report")
                            .small()
                            .w(px(160.))
                            .label("Export case report")
                            .on_click(cx.listener(|this, _, window, cx| this.export(window, cx))),
                    ),
            );
            for e in &case.document.evidence {
                let id = e.id.clone();
                page = page.child(
                    section(e.name(), cx)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .child(
                                    div()
                                        .text_xs()
                                        .flex_1()
                                        .min_w_0()
                                        .child(e.path.display().to_string()),
                                )
                                .child(div().text_xs().child(format!(
                                    "{} · OS: {}",
                                    format_bytes(e.size),
                                    e.operating_system.label()
                                ))),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .child(heading("SHA-256", cx))
                                .child(
                                    div()
                                        .text_xs()
                                        .font_family("Consolas")
                                        .flex_1()
                                        .min_w_0()
                                        .child(e.sha256.clone()),
                                )
                                .child(
                                    app_button(key("verify", &id))
                                        .small()
                                        .w(px(140.))
                                        .label("Verify integrity")
                                        .disabled(self.is_working())
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.selected_evidence = Some(id.clone());
                                            this.verify(cx);
                                        })),
                                ),
                        ),
                )
            }
        }
        self.scroll_state.page(scroll_state::ScrollArea::CaseInfo, page)
    }
}
