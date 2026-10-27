use super::*;

pub(in crate::ui) fn background() -> Hsla {
    rgb(0xc5a65a).into()
}

pub(in crate::ui) fn foreground() -> Hsla {
    rgb(0x171300).into()
}

pub(in crate::ui) fn badge(id: &'static str, label: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .flex_shrink_0()
        .px_2()
        .py_0p5()
        .rounded_sm()
        .border_1()
        .border_color(background().opacity(0.5))
        .bg(background().opacity(0.14))
        .text_color(rgb(0xe1ca91))
        .text_xs()
        .font_weight(FontWeight::MEDIUM)
        .child(label)
}

/// Paint behind the padded cells so selection and hover keep a continuous band.
pub(in crate::ui) fn highlight_row(row: Stateful<Div>) -> Stateful<Div> {
    row.relative()
        .text_color(foreground())
        .child(div().absolute().inset_0().bg(background()))
}

impl Workspace {
    pub(in crate::ui) fn is_partial_record(&self, id: i64) -> bool {
        self.row_cache
            .get(&id)
            .is_some_and(|stored| stored.record.is_partial_match())
    }

    pub(in crate::ui) fn toggle_partial_matches(&mut self, cx: &mut Context<Self>) {
        let mut settings = self.settings.clone();
        settings.show_partial_matches = !settings.show_partial_matches;
        if let Err(error) = settings.save() {
            self.error = Some(error);
            cx.notify();
            return;
        }
        self.settings = settings;
        if let Some(engine) = &mut self.installation {
            engine.settings.show_partial_matches = self.settings.show_partial_matches;
        }
        if !self.settings.show_partial_matches
            && self
                .selected
                .as_ref()
                .is_some_and(|r| r.record.is_partial_match())
        {
            self.selected = None;
            self.selected_row = None;
            self.selection_epoch += 1;
            self.reset_hex();
        }
        self.error = None;
        self.clear_result_tree();
        *self.network_cache.borrow_mut() = Default::default();
        self.start_query(cx);
        cx.notify();
    }
}
