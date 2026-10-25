// Displays cached file bytes without loading the entire dump into memory.
use super::*;
use volgui::extracted_files::HEX_PAGE_SIZE;

impl Workspace {
    pub(in crate::ui) fn render_hex_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let body = if self.content_encoding == volgui::extracted_files::ContentEncoding::Hex
            && let Some(editor) = &self.hex_editor
            && let HexView::Ready { files, page } = &self.hex_view
        {
            div()
                .size_full()
                .flex()
                .flex_col()
                .min_h_0()
                .min_w_0()
                .child(
                    div()
                        .px_3()
                        .py_2()
                        .child(self.render_file_actions(true, cx))
                        .child(self.render_content_controls(files, &page.path, cx)),
                )
                .child(div().flex_1().min_h_0().min_w_0().child(editor.clone()))
                .into_any_element()
        } else {
            div()
                .relative()
                .size_full()
                .min_h_0()
                .min_w_0()
                .child(
                    div()
                        .id("hex-content-scroll")
                        .size_full()
                        .overflow_scroll()
                        .track_scroll(&self.hex_scroll)
                        .p_3()
                        .child(self.render_file_actions(true, cx))
                        .child(self.render_hex(cx)),
                )
                .child(Scrollbar::vertical(&self.hex_scroll).mode(ScrollbarMode::Always))
                .child(Scrollbar::horizontal(&self.hex_scroll).mode(ScrollbarMode::Always))
                .into_any_element()
        };
        div()
            .size_full()
            .min_w_0()
            .min_h_0()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_2()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(heading("File contents", cx))
                    .child(
                        div().flex_1().min_w_0().truncate().text_xs().child(
                            self.selected
                                .as_ref()
                                .map(|record| record.record.title())
                                .unwrap_or_else(|| "Select a file".into()),
                        ),
                    ),
            )
            .child(div().relative().flex_1().min_h_0().min_w_0().child(body))
            .into_any_element()
    }

    fn render_content_controls(
        &self,
        files: &[PathBuf],
        selected_path: &std::path::Path,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut encodings = div().flex().flex_wrap().gap_1();
        for (i, encoding) in volgui::extracted_files::ContentEncoding::ALL
            .into_iter()
            .enumerate()
        {
            encodings = encodings.child(
                Button::new(("content-encoding", i))
                    .xsmall()
                    .ghost()
                    .label(encoding.label())
                    .selected(self.content_encoding == encoding)
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.set_content_encoding(encoding, cx)),
                    ),
            );
        }
        let mut choices = div().flex().flex_wrap().gap_1();
        for (i, file) in files.iter().enumerate() {
            let path = file.clone();
            choices = choices.child(
                Button::new(("hex-cache-file", i))
                    .xsmall()
                    .ghost()
                    .label(
                        file.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                    )
                    .selected(file == selected_path)
                    .tooltip(file.display().to_string())
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.read_hex_page(path.clone(), 0, cx)),
                    ),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(encodings)
            .child(choices)
    }

    pub(in crate::ui) fn render_hex(&self, cx: &mut Context<Self>) -> AnyElement {
        let application = self.result_group() == Some(ArtifactGroup::Applications);
        let mut content = div().flex().flex_col().gap_2().text_sm();
        match &self.hex_view {
            HexView::Idle => {
                content = content.child(if matches!(self.result_group(), Some(ArtifactGroup::Files | ArtifactGroup::Processes)) {
                    "Cached contents have not been recovered. Use Dump file in record details, or choose File and document recovery in New analysis."
                } else {
                    "No sidebar view is available for this content."
                });
            }
            HexView::Loading => {
                content = content.child("Loading file contents...");
            }
            HexView::Error(error) => {
                content = content.child(error.clone()).child(
                    Button::new("retry-hex")
                        .small()
                        .label("Retry")
                        .on_click(cx.listener(|this, _, _, cx| this.load_hex(cx))),
                );
            }
            HexView::Ready { files, page } => {
                if !application {
                    content = content.child(self.render_content_controls(files, &page.path, cx));
                }
                let previous_path = page.path.clone();
                let next_path = page.path.clone();
                let jump_path = page.path.clone();
                let previous = page.offset.saturating_sub(HEX_PAGE_SIZE);
                let next = page.offset.saturating_add(HEX_PAGE_SIZE);
                if !application
                    && self.content_encoding == volgui::extracted_files::ContentEncoding::Sqlite
                {
                    return content.child(self.render_database(cx)).into_any_element();
                }
                content = content.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap_2()
                        .child(
                            Button::new("hex-previous")
                                .xsmall()
                                .ghost()
                                .label("Previous")
                                .disabled(page.offset == 0)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.read_hex_page(previous_path.clone(), previous, cx)
                                })),
                        )
                        .child(div().child(format!(
                            "{:#x}..{:#x} of {} bytes",
                            page.offset,
                            page.offset + page.bytes.len() as u64,
                            page.total
                        )))
                        .child(
                            Button::new("hex-next")
                                .xsmall()
                                .ghost()
                                .label("Next")
                                .disabled(next >= page.total)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.read_hex_page(next_path.clone(), next, cx)
                                })),
                        )
                        .child(Input::new(&self.hex_offset).id("hex-offset-input").aria_label("Hex viewer byte offset").small().w(px(140.)))
                        .child(Button::new("hex-go").xsmall().ghost().label("Go to offset")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                let value = this.hex_offset.read(cx).value();
                                let value = value.trim();
                                let offset = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
                                    Some(hex) => u64::from_str_radix(hex, 16),
                                    None => value.parse::<u64>(),
                                };
                                match offset {
                                    Ok(offset) => this.read_hex_page(jump_path.clone(), offset, cx),
                                    Err(_) => { this.error = Some("Enter a decimal byte offset or hexadecimal offset beginning with 0x".into()); cx.notify(); }
                                }
                            }))),
                );
                if page.total == 0 {
                    content = content.child("This extracted file is empty.");
                }
                content = content.child(
                    div()
                        .font_family("Consolas")
                        .text_xs()
                        .min_w(px(640.))
                        .child(SelectableText::new(
                            "hex-bytes",
                            page.decoded(if application {
                                volgui::extracted_files::ContentEncoding::Hex
                            } else {
                                self.content_encoding
                            }),
                        )),
                );
            }
        }
        content.into_any_element()
    }

    fn render_database(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut content = div().flex().flex_col().gap_2();
        let page = match &self.database_view {
            None => {
                return content
                    .child("Reading database tables...")
                    .into_any_element();
            }
            Some(Err(error)) => return content.child(error.clone()).into_any_element(),
            Some(Ok(page)) => page,
        };
        let mut choices = div().flex().flex_wrap().gap_1();
        for (i, table) in page.tables.iter().enumerate() {
            let table = table.clone();
            let path = page.path.clone();
            choices = choices.child(
                Button::new(("database-table", i))
                    .xsmall()
                    .ghost()
                    .label(table.clone())
                    .selected(table == page.table)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.load_database(path.clone(), Some(table.clone()), 0, cx)
                    })),
            );
        }
        let previous = page.offset.saturating_sub(100);
        let next = page.offset + 100;
        let previous_path = page.path.clone();
        let next_path = page.path.clone();
        let previous_table = page.table.clone();
        let next_table = page.table.clone();
        self.database_table.update(cx, |state, cx| {
            if state.delegate().columns != page.columns {
                state.delegate_mut().columns = page.columns.clone();
                state.refresh(cx);
            }
            let location = (page.path.clone(), page.table.clone(), page.offset);
            if state.delegate().location.as_ref() != Some(&location) {
                state.delegate_mut().location = Some(location);
                state.scroll_to_row(0, cx);
            }
            cx.notify();
        });
        content = content.child(choices).child(div().text_xs().child("Read-only snapshot. 100 rows per page, cells limited to 1024 characters. Detached WAL data is not included."))
            .child(div().flex().items_center().gap_2()
                .child(Button::new("database-previous").xsmall().ghost().label("Previous rows").disabled(page.offset == 0).on_click(cx.listener(move |this,_,_,cx| this.load_database(previous_path.clone(),Some(previous_table.clone()),previous,cx))))
                .child(format!("{} rows at offset {}",page.rows.len(),page.offset))
                .child(Button::new("database-next").xsmall().ghost().label("Next rows").disabled(!page.more).on_click(cx.listener(move |this,_,_,cx| this.load_database(next_path.clone(),Some(next_table.clone()),next,cx)))))
            .child(div().id("database-rows").h(px(280.)).min_w_0()
                .child(DataTable::new(&self.database_table).small()));
        content.into_any_element()
    }
}
