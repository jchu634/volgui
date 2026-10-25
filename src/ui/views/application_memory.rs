//! A process memory reader with synchronized hex and decoded text.
use super::*;
use volgui::extracted_files::{ContentEncoding, HexPage};

impl Workspace {
    pub(in crate::ui) fn render_application_memory(&self, cx: &mut Context<Self>) -> AnyElement {
        let selected = self.selected.as_ref();
        let position = selected.and_then(|row| self.index.ids.iter().position(|id| *id == row.id));
        let marked = self
            .case
            .as_ref()
            .and_then(|case| case.annotation(self.selected_run.as_deref()?, self.selected_row?))
            .is_some_and(|a| a.bookmarked);
        let mut navigation = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .px_3()
            .py_2()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                Button::new("memory-previous-match")
                    .small()
                    .ghost()
                    .label("Previous match")
                    .disabled(position.is_none_or(|i| i == 0) || self.loading)
                    .on_click(cx.listener(|this, _, _, cx| this.step_application_match(false, cx))),
            )
            .child(div().text_sm().child(format!(
                "Match {} of {}",
                position.map_or(0, |i| i + 1),
                self.index.ids.len()
            )))
            .child(
                Button::new("memory-next-match")
                    .small()
                    .ghost()
                    .label("Next match")
                    .disabled(
                        self.loading || position.is_none_or(|i| i + 1 >= self.index.ids.len()),
                    )
                    .on_click(cx.listener(|this, _, _, cx| this.step_application_match(true, cx))),
            )
            .child(
                Button::new("memory-bookmark")
                    .small()
                    .ghost()
                    .label(if marked {
                        "Remove bookmark"
                    } else {
                        "Bookmark fragment"
                    })
                    .disabled(selected.is_none())
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_bookmark(cx))),
            );
        if let Some(row) = selected {
            navigation = navigation.child(div().text_xs().child(format!(
                "{} · PID {} · {} bytes",
                row.record.text("Process"),
                row.record.text("PID"),
                row.record.text("Byte length")
            )));
        }
        let hex = div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(div().px_3().py_2().child(heading("Hex bytes", cx)))
            .child(
                div()
                    .id("memory-hex-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_scroll()
                    .track_scroll(&self.hex_scroll)
                    .p_3()
                    .child(match &self.hex_view {
                        HexView::Idle => div()
                            .text_sm()
                            .child(
                                "Enter a PID and scan its memory, or select a recovered fragment.",
                            )
                            .into_any_element(),
                        _ => self.render_hex(cx),
                    }),
            );
        let mut text = div().flex().flex_col().size_full().min_w_0().min_h_0();
        let mut encodings = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_1()
            .px_3()
            .py_2()
            .child(heading("Decoded text", cx));
        for (i, encoding) in [
            ContentEncoding::Utf8,
            ContentEncoding::Utf16Le,
            ContentEncoding::Utf16Be,
        ]
        .into_iter()
        .enumerate()
        {
            encodings = encodings.child(
                Button::new(("memory-text-encoding", i))
                    .xsmall()
                    .ghost()
                    .label(encoding.label())
                    .selected(self.content_encoding == encoding)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.content_encoding = encoding;
                        cx.notify();
                    })),
            );
        }
        text = text.child(encodings);
        let mut decoded = div()
            .id("memory-decoded-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .track_scroll(&self.application_text_scroll)
            .p_3()
            .flex()
            .flex_col()
            .gap_3();
        match &self.hex_view {
            HexView::Ready { page, .. } => {
                let alignment = if matches!(
                    self.content_encoding,
                    ContentEncoding::Utf16Le | ContentEncoding::Utf16Be
                ) {
                    selected
                        .and_then(|r| r.record.fields.get("Dump offset")?.as_u64())
                        .map_or(0, |offset| (offset % 2) as usize)
                } else {
                    0
                };
                let alignment = alignment.min(page.bytes.len());
                let display = HexPage {
                    path: page.path.clone(),
                    offset: page.offset + alignment as u64,
                    total: page.total,
                    bytes: page.bytes[alignment..].to_vec(),
                };
                let encoding = if matches!(
                    self.content_encoding,
                    ContentEncoding::Utf16Le | ContentEncoding::Utf16Be
                ) {
                    self.content_encoding
                } else {
                    ContentEncoding::Utf8
                };
                let content = display
                    .decoded(encoding)
                    .replace("\r\n", "\n")
                    .replace('\r', "\n")
                    .chars()
                    .map(|c| {
                        if c.is_control() && !matches!(c, '\n' | '\t') {
                            '·'
                        } else {
                            c
                        }
                    })
                    .collect::<String>();
                decoded=decoded.child(heading(format!("Bytes {:#x}..{:#x}",display.offset,page.offset+page.bytes.len() as u64),cx))
                    .child(div().font_family("Consolas").text_sm().child(SelectableText::new("memory-decoded-page",content)))
                    .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Hex and text show the same dump page. Offsets are within the process dump; adjacent dumped pages may have different virtual addresses."));
            }
            HexView::Loading => {
                decoded = decoded.child("Loading process memory...");
            }
            HexView::Error(error) => {
                decoded = decoded.child(error.clone());
            }
            HexView::Idle => {
                decoded = decoded.child("Decoded bytes will appear beside the hex view.");
            }
        }
        if let Some(row) = selected {
            let fragment = row
                .record
                .text("Text")
                .replace("\r\n", "\n")
                .replace('\r', "\n");
            decoded=decoded.child(div().border_t_1().border_color(cx.theme().border).pt_3().child(heading("Recovered fragment",cx)))
                .child(div().font_family("Consolas").text_sm().child(SelectableText::new("memory-recovered-fragment",fragment)))
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Fragments can contain old edits or partial buffers. Their presence does not establish the current document or save state."));
        } else if self.index.ids.is_empty() {
            decoded = decoded.child(self.results_empty_message(cx));
        }
        text = text.child(decoded);
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(self.render_results_toolbar(cx))
            .child(self.render_investigation_tools(cx))
            .child(navigation)
            .child(
                div().flex_1().min_h_0().min_w_0().child(
                    h_resizable("application-memory-split")
                        .child(
                            resizable_panel()
                                .size(px(650.))
                                .size_range(px(300.)..Pixels::MAX)
                                .child(hex),
                        )
                        .child(
                            resizable_panel()
                                .size_range(px(260.)..Pixels::MAX)
                                .child(text),
                        ),
                ),
            )
            .into_any_element()
    }
}
