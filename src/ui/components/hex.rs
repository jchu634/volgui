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
        let mut encodings = div().flex().flex_1().min_w_0().flex_wrap().gap_1();
        for (i, encoding) in volgui::extracted_files::ContentEncoding::ALL
            .into_iter()
            .enumerate()
        {
            encodings = encodings.child(
                app_button(("content-encoding", i))
                    .xsmall()
                    .label(encoding.label())
                    .selected(self.content_encoding == encoding)
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.set_content_encoding(encoding, cx)),
                    ),
            );
        }
        // Keep file navigation bounded so large dumps leave room for the viewer.
        let selected_path = selected_path.to_path_buf();
        let choices = uniform_list(
            "hex-files-virtual",
            files.len(),
            cx.processor(move |this, range: Range<usize>, _, cx| {
                let HexView::Ready { files, .. } = &this.hex_view else {
                    return Vec::new();
                };
                range
                    .filter_map(|i| {
                        let file = files.get(i)?;
                        let path = file.clone();
                        Some(
                            div().h(px(28.)).w_full().min_w_0().overflow_hidden().child(
                                app_button(("hex-cache-file", i))
                                    .xsmall()
                                    .w_full()
                                    .justify_start()
                                    .label(
                                        file.file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .into_owned(),
                                    )
                                    .selected(file == &selected_path)
                                    .tooltip(file.display().to_string())
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.read_hex_page(path.clone(), 0, cx)
                                    })),
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .h(px((files.len() as f32 * 28.).min(112.)))
        .w_full();
        div()
            .flex()
            .flex_col()
            .gap_2()
            .min_w_0()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .w_full()
                    .min_w_0()
                    .items_center()
                    .gap_2()
                    .child(encodings)
                    .child(self.render_file_actions(true, cx)),
            )
            .child(choices)
    }

    pub(in crate::ui) fn render_hex(&self, cx: &mut Context<Self>) -> AnyElement {
        let application = self.result_group() == Some(ArtifactGroup::Applications);
        let mut content = div().flex().flex_col().gap_2().text_sm();
        match &self.hex_view {
            HexView::Idle => {
                if matches!(self.result_group(), Some(ArtifactGroup::Files | ArtifactGroup::Processes)) {
                    let file_target = self.selected.as_ref().and_then(|record| {
                        let source = self.case.as_ref()?.document.runs.iter()
                            .find(|run| run.id == record.run_id)?;
                        volgui::extracted_files::FileDumpTarget::from_record(&source.plugin, &record.record)
                    }).is_some();
                    let process_target = self.result_group() == Some(ArtifactGroup::Processes)
                        && self.selected.as_ref().is_some_and(|record| {
                            ["PID", "Pid", "pid"].iter().any(|key| record.record.text(key).parse::<u64>().is_ok())
                        });
                    let available = (file_target || process_target)
                        && self.busy.is_none()
                        && self.installation.as_ref().is_some_and(|engine| {
                            engine.plugins.iter().any(|plugin| plugin.id == volgui::extracted_files::DUMP_FILES)
                        });
                    content = content.child(
                        div().text_xs().text_color(cx.theme().muted_foreground).child(
                            if file_target {
                                "Recover this file's cached contents from memory and view them here."
                            } else {
                                "Recover cached files from this process and view them here."
                            },
                        ),
                    ).child(
                        app_button("dump-load-sidebar-files")
                            .self_start()
                            .small()
                            .label("Dump and Load files")
                            .disabled(!available)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                if file_target {
                                    this.dump_file(false, true, window, cx);
                                } else {
                                    this.collect_process_files(window, cx);
                                }
                            })),
                    );
                } else {
                    content = content.child("No sidebar view is available for this content.");
                }
            }
            HexView::NeedsMemory => {
                content = content.child(
                    div().text_xs().text_color(cx.theme().muted_foreground)
                        .child("Collect this process's memory to view the bytes surrounding this result."),
                ).child(
                    app_button("load-scan-memory")
                        .self_start()
                        .small()
                        .label("Load memory")
                        .disabled(self.loading)
                        .on_click(cx.listener(|this, _, _, cx| this.view_memory_scan(cx))),
                );
            }
            HexView::Loading => {
                content = content.child(if self.memory_scan_dump.is_some() {
                    "Collecting process memory. The hex view will open when the analysis finishes."
                } else {
                    "Loading file contents..."
                });
            }
            HexView::Error(error) => {
                content = content.child(error.clone()).child(
                    app_button("retry-hex")
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
                            app_button("hex-previous")
                                .xsmall()

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
                            app_button("hex-next")
                                .xsmall()

                                .label("Next")
                                .disabled(next >= page.total)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.read_hex_page(next_path.clone(), next, cx)
                                })),
                        )
                        .child(Input::new(&self.hex_offset).id("hex-offset-input").aria_label("Hex viewer byte offset").small().w(px(140.)))
                        .child(app_button("hex-go").xsmall().label("Go to offset")
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
                app_button(("database-table", i))
                    .xsmall()
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
                .child(app_button("database-previous").xsmall().label("Previous rows").disabled(page.offset == 0).on_click(cx.listener(move |this,_,_,cx| this.load_database(previous_path.clone(),Some(previous_table.clone()),previous,cx))))
                .child(format!("{} rows at offset {}",page.rows.len(),page.offset))
                .child(app_button("database-next").xsmall().label("Next rows").disabled(!page.more).on_click(cx.listener(move |this,_,_,cx| this.load_database(next_path.clone(),Some(next_table.clone()),next,cx)))))
            .child(div().id("database-rows").h(px(280.)).min_w_0()
                .child(DataTable::new(&self.database_table).small()));
        content.into_any_element()
    }
}
