// Renders case metadata and evidence verification.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_case_info(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("case-info-page")
            .flex_1()
            .overflow_y_scrollbar()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_xl().child("Case information"));
        if let Some(case) = &self.case {
            page = page
                .child(div().text_sm().child(case.document.name.clone()))
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(case.directory.display().to_string()),
                )
                .child(
                    Button::new("export-report")
                        .small()
                        .w(px(160.))
                        .label("Export case report")
                        .on_click(cx.listener(|this, _, window, cx| this.export(true, window, cx))),
                );
            for e in &case.document.evidence {
                let id = e.id.clone();
                page = page.child(
                    section(e.name(), cx)
                        .child(div().text_xs().child(e.path.display().to_string()))
                        .child(div().text_xs().child(format!(
                            "{} · OS: {}",
                            format_bytes(e.size),
                            e.operating_system.label()
                        )))
                        .child(heading("SHA-256", cx))
                        .child(
                            div()
                                .text_xs()
                                .font_family("Consolas")
                                .child(e.sha256.clone()),
                        )
                        .child(
                            Button::new(key("verify", &id))
                                .small()
                                .w(px(140.))
                                .label("Verify integrity")
                                .disabled(self.busy.is_some())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.selected_evidence = Some(id.clone());
                                    this.verify(cx);
                                })),
                        ),
                )
            }
        }
        page.into_any_element()
    }
}
