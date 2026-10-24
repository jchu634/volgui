// Renders bookmarked result records.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_bookmarks(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("bookmarks-page")
            .flex_1()
            .overflow_y_scrollbar()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().text_xl().child("Bookmarks"));
        if let Some(case) = &self.case {
            for (i, a) in case
                .document
                .annotations
                .iter()
                .filter(|a| a.bookmarked)
                .enumerate()
            {
                let run = a.run_id.clone();
                let row = a.row;
                let title = case
                    .document
                    .runs
                    .iter()
                    .find(|r| r.id == run)
                    .map(|r| r.plugin.clone())
                    .unwrap_or_default();
                page = page.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .px_3()
                        .py_2()
                        .border_1()
                        .border_color(cx.theme().border)
                        .rounded_md()
                        .child(
                            div().flex_1().min_w_0().child(
                                div()
                                    .text_sm()
                                    .truncate()
                                    .child(format!("{title} · row {}", row + 1)),
                            ),
                        )
                        .child(
                            Button::new(("open-bookmark", i))
                                .small()
                                .label("Open")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.load_annotation(run.clone(), row, cx)
                                })),
                        ),
                );
            }
        }
        page.into_any_element()
    }
}
