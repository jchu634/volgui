// Renders record fields, diagnostics, extracted files, and bookmarks.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_file_actions(&self, for_hex: bool, cx: &mut Context<Self>) -> Div {
        let prefix = if for_hex { "hex" } else { "details" };
        let target = self.selected.as_ref().and_then(|record| {
            let run = self
                .case
                .as_ref()?
                .document
                .runs
                .iter()
                .find(|run| run.id == record.run_id)?;
            volgui::extracted_files::FileDumpTarget::from_record(&run.plugin, &record.record)
        });
        let Some(target) = target else {
            return div();
        };
        let available = self.installation.as_ref().is_some_and(|engine| {
            engine
                .plugins
                .iter()
                .any(|plugin| plugin.id == volgui::extracted_files::DUMP_FILES)
        }) && !self.busy.as_ref().is_some_and(|busy| busy.run_id.is_none());
        let imhex = volgui::extracted_files::imhex().is_some();
        let mut actions = div().flex().flex_wrap().items_center().gap_2().mb_2();
        if target.needs_address_space() {
            actions = actions.child(
                    Button::new(key("file-offset-space", prefix))
                        .small()
                        .ghost()
                        .label(if self.file_offset_physical { "Physical offset" } else { "Virtual offset" })
                        .tooltip("Click to switch. FileScan uses virtual offsets on Windows 10 and later, physical offsets on older Windows.")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.file_offset_physical = !this.file_offset_physical;
                            this.reset_hex();
                            if this.hex_visible { this.load_hex(cx); }
                            cx.notify();
                        })),
                );
        }
        actions
            .child(
                Button::new(key("dump-selected-file", prefix))
                    .small()
                    .label(if for_hex {
                        "Extract and view hex"
                    } else {
                        "Dump file"
                    })
                    .disabled(!available)
                    .tooltip(if available {
                        "Extract only this file from memory"
                    } else {
                        "Configure Volatility with the Windows DumpFiles plugin in Settings"
                    })
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.dump_file(false, for_hex, window, cx)
                    })),
            )
            .child(
                Button::new(key("dump-selected-file-imhex", prefix))
                    .small()
                    .label("Dump and open in ImHex")
                    .disabled(!available || !imhex)
                    .tooltip(if !imhex {
                        "Install ImHex in its default location or add it to PATH"
                    } else {
                        "Extract this file and open its cached contents in ImHex"
                    })
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.dump_file(true, for_hex, window, cx)
                    })),
            )
    }

    pub(in crate::ui) fn render_details(&self, cx: &mut Context<Self>) -> AnyElement {
        let record = self.selected.as_ref();
        let marked = self
            .case
            .as_ref()
            .and_then(|case| case.annotation(self.selected_run.as_deref()?, self.selected_row?))
            .is_some_and(|a| a.bookmarked);
        let mut tabs = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_1()
            .px_3()
            .border_b_1()
            .border_color(cx.theme().border);
        for (id, label, tab) in [
            ("overview", "Overview", DetailTab::Overview),
            ("raw", "Raw JSON", DetailTab::Raw),
            ("diagnostics", "Run details", DetailTab::Diagnostics),
            ("files", "Extracted files", DetailTab::Files),
            ("handles", "Handles", DetailTab::Handles),
        ] {
            tabs = tabs.child(
                Button::new(id)
                    .small()
                    .ghost()
                    .label(label)
                    .selected(self.detail == tab)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.detail = tab;
                        if tab == DetailTab::Handles {
                            this.load_handles(0, cx);
                        }
                        cx.notify();
                    })),
            );
        }
        let mut content = div()
            .id("artifact-details-scroll")
            .track_scroll(&self.details_scroll)
            .overflow_scroll()
            .p_3()
            .size_full();
        if matches!(self.detail, DetailTab::Overview | DetailTab::Files) {
            content = content.child(self.render_file_actions(false, cx));
        }
        match self.detail {
            DetailTab::Handles => {
                content = content.child(self.render_handles(cx));
            }
            DetailTab::Overview => {
                if let Some(record) = record {
                    if let Some(source) = record
                        .record
                        .fields
                        .get("Source run")
                        .and_then(|v| v.as_str())
                    {
                        let source = source.to_string();
                        content = content.child(
                            Button::new("open-finding-source")
                                .small()
                                .ghost()
                                .label("Open source extraction")
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.select_run(source.clone(), window, cx)
                                })),
                        );
                    }
                    let mut fields = div().flex().flex_wrap().gap_x_4().items_start().w_full();
                    for (i, (name, value)) in record.record.fields.iter().enumerate() {
                        let text = display_value(value);
                        let parent = self
                            .relations
                            .parent
                            .as_ref()
                            .filter(|_| name.eq_ignore_ascii_case("ppid"));
                        fields = fields.child(
                            div()
                                .flex()
                                .flex_basis(px(340.))
                                .flex_grow_1()
                                .min_w_0()
                                .max_w_full()
                                .when(text.chars().count() > 72 || text.contains('\n'), |field| {
                                    field.flex_basis(relative(1.))
                                })
                                .items_start()
                                .gap_2()
                                .py_1()
                                .border_b_1()
                                .border_color(cx.theme().border)
                                .child(
                                    div()
                                        .w(px(104.))
                                        .flex_shrink_0()
                                        .text_xs()
                                        .text_color(cx.theme().muted_foreground)
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(|this, _, window, cx| {
                                                window.focus(&this.workspace_focus, cx)
                                            }),
                                        )
                                        .child(SelectableText::new(
                                            ("field-name", i),
                                            name.clone(),
                                        )),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .text_sm()
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(|this, _, window, cx| {
                                                window.focus(&this.workspace_focus, cx)
                                            }),
                                        )
                                        .map(|cell| {
                                            if let Some(parent) = parent {
                                                let id = parent.id;
                                                cell.child(
                                                    record_link(
                                                        "parent-process",
                                                        format!("{text} · {}", parent.title),
                                                        cx,
                                                    )
                                                    .on_activate(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.load_record(id, cx)
                                                        },
                                                    )),
                                                )
                                                .into_any_element()
                                            } else {
                                                cell.child(SelectableText::new(
                                                    ("field-value", i),
                                                    text.clone(),
                                                ))
                                                .into_any_element()
                                            }
                                        }),
                                )
                                .child(
                                    Button::new(("copy-field", i))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::Copy)
                                        .tooltip("Copy value")
                                        .on_click(move |_, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                text.clone(),
                                            ))
                                        }),
                                ),
                        );
                    }
                    content = content.child(fields);
                    if let Some(parent) = self.relations.parent.as_ref().filter(|_| {
                        !record
                            .record
                            .fields
                            .keys()
                            .any(|k| k.eq_ignore_ascii_case("ppid"))
                    }) {
                        let id = parent.id;
                        content = content.child(
                            record_link(
                                "related-parent-process",
                                format!(
                                    "Parent: {} · PID {}",
                                    parent.title,
                                    parent.pid.as_deref().unwrap_or("")
                                ),
                                cx,
                            )
                            .on_activate(
                                cx.listener(move |this, _, _, cx| this.load_record(id, cx)),
                            ),
                        );
                    }
                    if !self.relations.children.is_empty() {
                        let children = self.relations.children.clone();
                        let height = px((children.len() as f32 * 28.).min(112.));
                        let list = uniform_list(
                            "process-children",
                            children.len(),
                            cx.processor(move |_, range: Range<usize>, _, cx| {
                                range
                                    .map(|i| {
                                        let child = &children[i];
                                        let id = child.id;
                                        Button::new(key("child-process", &id.to_string()))
                                            .small()
                                            .ghost()
                                            .justify_start()
                                            .h(px(28.))
                                            .label(format!(
                                                "{} · PID {}",
                                                child.title,
                                                child.pid.as_deref().unwrap_or("")
                                            ))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.load_record(id, cx)
                                            }))
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        )
                        .track_scroll(&self.relations_scroll)
                        .h_full();
                        content = content.child(
                            div()
                                .mt_2()
                                .child(heading(
                                    format!("CHILD PROCESSES ({})", self.relations.children.len()),
                                    cx,
                                ))
                                .child(
                                    div().relative().h(height).child(list).child(
                                        Scrollbar::vertical(&self.relations_scroll)
                                            .mode(ScrollbarMode::Always),
                                    ),
                                ),
                        );
                    }
                } else {
                    content=content.child(div().text_sm().text_color(cx.theme().muted_foreground).child("Select a result to inspect its fields. Add evidence or choose analyses to load results."));
                }
            }
            DetailTab::Raw => {
                if let Some(record) = record {
                    content = content.child(
                        div()
                            .flex()
                            .gap_2()
                            .mb_2()
                            .child(
                                Button::new("toggle-json-expansion")
                                    .xsmall()
                                    .ghost()
                                    .label(if self.raw_expand_all {
                                        "Collapse all"
                                    } else {
                                        "Expand all"
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.raw_expand_all = !this.raw_expand_all;
                                        this.raw_expanded.clear();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("copy-json")
                                    .xsmall()
                                    .ghost()
                                    .icon(IconName::Copy)
                                    .label("Copy JSON")
                                    .on_click({
                                        let json =
                                            serde_json::to_string_pretty(&record.record.fields)
                                                .unwrap_or_default();
                                        move |_, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                json.clone(),
                                            ))
                                        }
                                    }),
                            ),
                    );
                    for (key, value) in &record.record.fields {
                        let path = format!("/{}", key.replace('~', "~0").replace('/', "~1"));
                        content = content.child(self.json_node(&path, key, value, 0, cx));
                    }
                }
            }
            DetailTab::Files => {
                if let Some((case, run)) = self.case.as_ref().and_then(|case| {
                    case.document
                        .runs
                        .iter()
                        .find(|run| Some(&run.id) == self.selected_run.as_ref())
                        .map(|run| (case, run))
                }) {
                    let run = record
                        .and_then(|record| {
                            volgui::extracted_files::completed_dump(
                                case,
                                record,
                                self.file_offset_physical,
                            )
                        })
                        .unwrap_or(run);
                    let directory = case.run_dir(&run.id);
                    match volgui::extracted_files::list(&directory) {
                        Ok(files) if files.is_empty() => {
                            content = content.child("No extracted files. Select a file-scan result and choose Dump file, or run a dump plugin.");
                        }
                        Ok(files) => {
                            let imhex = volgui::extracted_files::imhex();
                            if imhex.is_none() {
                                content = content.child(div().text_sm().child("ImHex was not found. Install it in its default location or add it to PATH to open files here."));
                            }
                            for (i, file) in files.iter().cloned().enumerate() {
                                let source = file.clone();
                                let hex_file = file.clone();
                                let hex_files = files.clone();
                                let mut row = div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .py_1()
                                    .child(
                                        div().flex_1().text_sm().child(
                                            file.strip_prefix(&directory)
                                                .unwrap_or(&file)
                                                .display()
                                                .to_string(),
                                        ),
                                    )
                                    .child(
                                        Button::new(("hex-extracted", i))
                                            .small()
                                            .label("View hex")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.open_hex_file(
                                                    hex_files.clone(),
                                                    hex_file.clone(),
                                                    0,
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(
                                        Button::new(("save-extracted", i))
                                            .small()
                                            .label("Save as...")
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.export_file(source.clone(), window, cx)
                                            })),
                                    );
                                if let Some(executable) = imhex.clone() {
                                    row = row.child(
                                        Button::new(("imhex-extracted", i))
                                            .small()
                                            .label("Open in ImHex")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                match volgui::extracted_files::open(
                                                    &executable,
                                                    &file,
                                                ) {
                                                    Ok(()) => {
                                                        this.message = "Opened in ImHex".into()
                                                    }
                                                    Err(error) => {
                                                        this.error = Some(format!(
                                                            "Could not open ImHex: {error}"
                                                        ))
                                                    }
                                                }
                                                cx.notify();
                                            })),
                                    );
                                }
                                content = content.child(row);
                            }
                        }
                        Err(error) => {
                            content =
                                content.child(format!("Could not list extracted files: {error}"))
                        }
                    }
                } else {
                    content = content.child("Select an analysis to view its extracted files.");
                }
            }
            DetailTab::Diagnostics => {
                if let Some(run) = self.case.as_ref().and_then(|c| {
                    c.document
                        .runs
                        .iter()
                        .find(|r| Some(&r.id) == self.selected_run.as_ref())
                }) {
                    let text = format!(
                        "{} · {} records · exit {:?}\n{}\nStarted {}\nFinished {}\n\n{}\n\n{}",
                        run.status.label(),
                        run.row_count,
                        run.exit_code,
                        run.engine_version,
                        run.started_at.as_deref().unwrap_or("Not started"),
                        run.finished_at.as_deref().unwrap_or("Not finished"),
                        serde_json::to_string_pretty(&run.command).unwrap_or_default(),
                        run.message
                    );
                    let output = self.case.as_ref().unwrap().run_dir(&run.id);
                    content = content
                        .child(
                            div()
                                .text_xs()
                                .font_family("Consolas")
                                .child(SelectableText::new("run-diagnostics", text)),
                        )
                        .child(
                            Button::new("show-output")
                                .small()
                                .label("Show output directory")
                                .on_click(move |_, _, cx| cx.reveal_path(&output)),
                        );
                }
            }
        }
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
                    .py_1()
                    .child(
                        div().flex_1().min_w_0().text_sm().truncate().child(
                            record
                                .map(|r| r.record.title())
                                .unwrap_or_else(|| "Artifact details".into()),
                        ),
                    )
                    .when(record.is_some(), |header| {
                        header.child(
                            Button::new("bookmark")
                                .xsmall()
                                .ghost()
                                .icon(IconName::Bookmark)
                                .selected(marked)
                                .tooltip(if marked {
                                    "Remove bookmark"
                                } else {
                                    "Bookmark artifact"
                                })
                                .on_click(cx.listener(|this, _, _, cx| this.toggle_bookmark(cx))),
                        )
                    }),
            )
            .child(tabs)
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(div().size_full().child(content))
                    .child(Scrollbar::vertical(&self.details_scroll).mode(ScrollbarMode::Always))
                    .child(Scrollbar::horizontal(&self.details_scroll).mode(ScrollbarMode::Always)),
            )
            .into_any_element()
    }
    pub(in crate::ui) fn json_node(
        &self,
        path: &str,
        name: &str,
        value: &serde_json::Value,
        depth: usize,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let expandable = value.is_array() || value.is_object();
        let expanded = self.raw_expand_all ^ self.raw_expanded.contains(path);
        let mut row = div()
            .flex()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| window.focus(&this.workspace_focus, cx)),
            )
            .items_center()
            .gap_2()
            .h(px(26.))
            .pl(px(depth as f32 * 16.))
            .text_xs()
            .font_family("Consolas");
        if expandable {
            let path = path.to_string();
            row = row.child(
                Button::new(key("json-toggle", &path))
                    .xsmall()
                    .ghost()
                    .icon(if expanded {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if !this.raw_expanded.remove(&path) {
                            this.raw_expanded.insert(path.clone());
                        }
                        cx.notify();
                    })),
            );
        } else {
            row = row.child(div().w(px(20.)));
        }
        let summary = match value {
            serde_json::Value::Array(v) => format!("[{} items]", v.len()),
            serde_json::Value::Object(v) => format!("{{{} fields}}", v.len()),
            _ => serde_json::to_string(value).unwrap_or_default(),
        };
        row = row.child(SelectableText::new(
            key("json-value", path),
            format!("{name}: {summary}"),
        ));
        let mut node = div().flex().flex_col().child(row);
        if expandable && expanded && depth < 64 {
            match value {
                serde_json::Value::Array(values) => {
                    for (i, value) in values.iter().enumerate() {
                        node = node.child(self.json_node(
                            &format!("{path}/{i}"),
                            &i.to_string(),
                            value,
                            depth + 1,
                            cx,
                        ));
                    }
                }
                serde_json::Value::Object(values) => {
                    for (key, value) in values {
                        node = node.child(self.json_node(
                            &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                            key,
                            value,
                            depth + 1,
                            cx,
                        ));
                    }
                }
                _ => {}
            }
        }
        node.into_any_element()
    }
}
