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
                app_button("memory-previous-match")
                    .small()
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
                app_button("memory-next-match")
                    .small()
                    .label("Next match")
                    .disabled(
                        self.loading || position.is_none_or(|i| i + 1 >= self.index.ids.len()),
                    )
                    .on_click(cx.listener(|this, _, _, cx| this.step_application_match(true, cx))),
            )
            .child(
                app_button("memory-bookmark")
                    .small()
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
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(self.render_memory_hex(cx)),
            );
        let mut text = div().flex().flex_col().size_full().min_w_0().min_h_0();
        let mut encodings = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_1()
            .px_3()
            .py_2()
            .child(heading("Decode selection", cx));
        for (i, encoding) in [
            ContentEncoding::Utf8,
            ContentEncoding::Utf16Le,
            ContentEncoding::Utf16Be,
        ]
        .into_iter()
        .enumerate()
        {
            encodings = encodings.child(
                app_button(("memory-text-encoding", i))
                    .xsmall()
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
                let preview = self
                    .hex_editor
                    .as_ref()
                    .and_then(|editor| editor.read(cx).selection());
                if let Some(preview) = preview {
                    decoded = decoded.child(heading(
                        format!(
                            "Bytes {:#x}..{:#x} · {} selected",
                            preview.range.start,
                            preview.range.end,
                            preview.range.end - preview.range.start,
                        ),
                        cx,
                    ));
                    match &preview.bytes {
                        Some(Ok(bytes)) => {
                            let encoding = match self.content_encoding {
                                ContentEncoding::Utf16Le | ContentEncoding::Utf16Be => {
                                    self.content_encoding
                                }
                                _ => ContentEncoding::Utf8,
                            };
                            let display = HexPage {
                                path: page.path.clone(),
                                offset: preview.range.start,
                                total: page.total,
                                bytes: bytes.to_vec(),
                            };
                            let content = display
                                .decoded(encoding)
                                .replace("\r\n", "\n")
                                .replace('\r', "\n");
                            decoded =
                                decoded
                                    .child(div().font_family("Consolas").text_sm().child(
                                        SelectableText::new("memory-decoded-selection", content),
                                    ))
                                    .when(
                                        preview.range.end - preview.range.start
                                            > bytes.len() as u64,
                                        |view| {
                                            view.child(
                                    div().text_xs().text_color(cx.theme().muted_foreground)
                                        .child("Showing the first 64 KiB of the selection."))
                                        },
                                    )
                                    .when(
                                        matches!(
                                            encoding,
                                            ContentEncoding::Utf16Le | ContentEncoding::Utf16Be
                                        ) && bytes.len() % 2 != 0,
                                        |view| {
                                            view.child(
                                    div().text_xs().text_color(cx.theme().muted_foreground)
                                        .child("The trailing byte is incomplete for UTF-16."))
                                        },
                                    )
                                    .child(self.render_memory_numbers(bytes, cx));
                        }
                        Some(Err(error)) => decoded = decoded.child(error.clone()),
                        None => decoded = decoded.child("Reading selected bytes..."),
                    }
                } else {
                    decoded = decoded
                        .child("Select bytes in the hex or UTF-8 columns to decode them here.");
                }
                decoded = decoded.child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Offsets are within the process dump. Adjacent dump rows may have different virtual address mappings. Text decoding starts at the first selected byte."));
            }
            HexView::Loading => {
                decoded = decoded.child("Loading process memory...");
            }
            HexView::Error(error) => {
                decoded = decoded.child(error.clone());
            }
            HexView::Idle | HexView::NeedsMemory => {
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
        let body = if self.content_sidebar_visible {
            h_resizable("application-memory-split")
                .child(
                    resizable_panel()
                        .size(px(800.))
                        .size_range(px(300.)..Pixels::MAX)
                        .child(hex),
                )
                .child(
                    resizable_panel()
                        .size(px(380.))
                        .size_range(px(260.)..Pixels::MAX)
                        .child(text),
                )
                .into_any_element()
        } else {
            hex.into_any_element()
        };
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(self.render_results_toolbar(cx))
            .child(self.render_investigation_tools(cx))
            .child(navigation)
            .child(div().flex_1().min_h_0().min_w_0().child(body))
            .into_any_element()
    }

    fn render_memory_hex(&self, cx: &mut Context<Self>) -> AnyElement {
        if let Some(editor) = &self.hex_editor {
            return editor.clone().into_any_element();
        }
        let message = match &self.hex_view {
            HexView::Idle | HexView::NeedsMemory => "Enter a PID and scan its memory, or select a recovered fragment.",
            HexView::Loading => "Loading process memory...",
            HexView::Error(error) => error.as_str(),
            HexView::Ready { .. } => "Preparing hex editor...",
        };
        div()
            .p_3()
            .text_sm()
            .child(message.to_owned())
            .when(matches!(self.hex_view, HexView::Error(_)), |s| {
                s.child(
                    app_button("memory-hex-retry")
                        .small()
                        .label("Retry")
                        .on_click(cx.listener(|this, _, _, cx| this.load_hex(cx))),
                )
            })
            .into_any_element()
    }

    fn render_memory_numbers(&self, bytes: &[u8], cx: &App) -> AnyElement {
        let mut values = div()
            .flex()
            .flex_col()
            .gap_1()
            .text_xs()
            .border_t_1()
            .border_color(cx.theme().border)
            .pt_3()
            .child(heading("Values at selection start", cx));
        let mut rows = Vec::new();
        if let Some(byte) = bytes.first() {
            rows.push(("u8 / i8", format!("{} / {}", byte, *byte as i8), "".into()));
        }
        macro_rules! value {
            ($ty:ty, $width:expr) => {
                if let Some(slice) = bytes.get(..$width) {
                    let data: [u8; $width] = slice.try_into().unwrap();
                    rows.push((
                        stringify!($ty),
                        format!("{:?}", <$ty>::from_le_bytes(data)),
                        format!("{:?}", <$ty>::from_be_bytes(data)),
                    ));
                }
            };
        }
        value!(u16, 2);
        value!(i16, 2);
        value!(u32, 4);
        value!(i32, 4);
        value!(f32, 4);
        value!(u64, 8);
        value!(i64, 8);
        value!(f64, 8);
        values = values.child(
            div()
                .flex()
                .gap_2()
                .child(div().w(px(56.)))
                .child(div().flex_1().child("Little endian"))
                .child(div().flex_1().child("Big endian")),
        );
        for (i, (label, little, big)) in rows.into_iter().enumerate() {
            values = values.child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().w(px(56.)).flex_shrink_0().child(label))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(SelectableText::new(("memory-number-le", i), little)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(SelectableText::new(("memory-number-be", i), big)),
                    ),
            );
        }
        values.into_any_element()
    }
}
