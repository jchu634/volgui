use super::*;

impl Workspace {
    fn search_history_dropdown(&self, process: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let mut history = Vec::new();
        if let Some(case) = &self.case {
            for run in case.document.runs.iter().rev().filter(|run| {
                Some(&run.evidence_id) == self.selected_evidence.as_ref()
                    && run.plugin
                        == if process {
                            volgui::analysis::APPLICATION
                        } else {
                            volgui::analysis::STRINGS
                        }
            }) {
                let value = if process {
                    volgui::analysis::application::target_pid(&run.arguments)
                        .ok()
                        .map(|pid| pid.to_string())
                } else {
                    run.arguments.first().cloned()
                };
                if let Some(value) = value.filter(|value| !value.is_empty())
                    && !history.contains(&value)
                {
                    history.push(value);
                }
            }
        }
        let weak = cx.entity().downgrade();
        Button::new(if process {
            "pid-search-history"
        } else {
            "string-search-history"
        })
        .small()
        .ghost()
        .dropdown_caret(true)
        .tooltip("Previous searches")
        .disabled(history.is_empty())
        .dropdown_menu(move |mut menu, _, _| {
            for value in &history {
                let value = value.clone();
                let weak = weak.clone();
                menu = menu.item(PopupMenuItem::new(value.clone()).on_click(
                    move |_, window, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            if process {
                                let saved = this.case.as_ref().and_then(|case| {
                                    case.document
                                        .runs
                                        .iter()
                                        .rev()
                                        .find(|run| {
                                            Some(&run.evidence_id)
                                                == this.selected_evidence.as_ref()
                                                && run.plugin == volgui::analysis::APPLICATION
                                                && run.status == RunStatus::Completed
                                                && volgui::analysis::application::target_pid(
                                                    &run.arguments,
                                                )
                                                .is_ok_and(|pid| pid.to_string() == value)
                                        })
                                        .map(|run| run.id.clone())
                                });
                                if let Some(id) = saved {
                                    this.select_run(id, window, cx);
                                    return;
                                }
                            }
                            let input = if process {
                                &this.application_pid
                            } else {
                                &this.string_needle
                            };
                            input
                                .update(cx, |input, cx| input.set_value(value.clone(), window, cx));
                            cx.notify();
                        });
                    },
                ));
            }
            menu
        })
    }

    pub(in crate::ui) fn render_investigation_tools(&self, cx: &mut Context<Self>) -> Div {
        let mut tools = div()
            .flex()
            .flex_col()
            .w_full()
            .min_w_0()
            .flex_shrink_0()
            .gap_2()
            .px_3()
            .py_2();
        match self.result_group() {
            Some(ArtifactGroup::Downloads) => {
                tools = tools.child(div().text_xs().child("Start with a website or filename. Select a finding to follow download origins, process evidence and remote connections. Filename matches and residual bytes are candidates; a port alone does not identify a reverse shell."))
                    .child(div().flex().flex_wrap().w_full().min_w_0().items_center().gap_2()
                        .child(Button::new("investigate-downloads").small().primary().label("Start analysis")
                            .disabled(self.is_working() || self.installation.is_none() || self.evidence().is_none())
                            .on_click(cx.listener(|this, _, window, cx| this.analyze_downloads(window,cx))))
                        .child(Button::new("download-all-findings").small().ghost().label("All findings")
                            .on_click(cx.listener(|this,_,_,cx| { this.column_filters.clear();this.start_query(cx); })))
                        .child(Button::new("download-browser-activity").small().ghost().label("Browser activity")
                            .on_click(cx.listener(|this, _, window, cx| this.choose_group(ArtifactGroup::Web,window,cx))))
                        .child(Button::new("download-network").small().ghost().label("All network connections")
                            .on_click(cx.listener(|this, _, window, cx| this.choose_group(ArtifactGroup::Network,window,cx)))));
            }
            Some(ArtifactGroup::Applications) => {
                tools = tools.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap_2()
                        .child("PID")
                        .child(
                            Input::new(&self.application_pid)
                                .id("application-memory-pid")
                                .aria_label("Process ID to scan")
                                .small()
                                .w(px(150.)),
                        )
                        .child(self.search_history_dropdown(true, cx))
                        .child(
                            Button::new("scan-application-memory")
                                .small()
                                .primary()
                                .label("Scan")
                                .disabled(
                                    self.evidence().is_none()
                                        || self.busy.is_some()
                                        || self.installation.is_none(),
                                )
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.scan_application_memory(None, window, cx)
                                })),
                        ),
                );
            }
            Some(ArtifactGroup::Web) => {
                tools = tools.child(div().text_xs().child("Recover browser memory, history and saved tabs, then analyze URLs and searches.\n Memory findings may include stale strings and do not alone prove a visit."))
                    .child(div().flex().items_center().child(Button::new("recover-analyze-browser").small().label("Start analysis")
                        .disabled(self.is_working() || self.browser_recovery_pending || self.installation.is_none())
                        .on_click(cx.listener(|this, _, window, cx| this.recover_and_analyze_browser(window, cx)))));
            }
            Some(ArtifactGroup::Strings) => {
                tools = tools.child(div().text_xs().child("Search the selected evidence file for a literal string in UTF-8, UTF-16LE and UTF-16BE. Results include byte offsets and context. Maximum 10,000 matches per analysis."))
                    .child(div().flex().items_center().gap_2()
                        .child(Input::new(&self.string_needle).id("global-string-needle").aria_label("String to find in evidence").small().w(px(360.)))
                        .child(self.search_history_dropdown(false, cx))
                        .child(Checkbox::new("string-ignore-case").label("Ignore ASCII case").checked(self.string_ignore_case).on_click(cx.listener(|this,checked,_,cx| { this.string_ignore_case = *checked; cx.notify(); })))
                        .child(Button::new("run-global-search").small().label("Search").disabled(self.evidence().is_none() || self.busy.is_some()).on_click(cx.listener(|this,_,window,cx| this.run_string_search(window,cx)))));
            }
            Some(ArtifactGroup::Registry) => {
                let child = self
                    .selected
                    .as_ref()
                    .and_then(|r| {
                        let run = self
                            .case
                            .as_ref()?
                            .document
                            .runs
                            .iter()
                            .find(|run| run.id == r.run_id)?;
                        volgui::analysis::registry::child_key(run, &r.record)
                    })
                    .is_some();
                tools = tools.child(div().text_xs().child("Expand branches to inspect collected registry keys and values. Select a key and choose Open subkey to collect its contents."))
                    .child(div().flex().flex_wrap().items_center().gap_2()
                        .child(Button::new("find-registry-hives").small().ghost().label("Find hives").disabled(self.installation.is_none()).on_click(cx.listener(|this,_,window,cx| this.collect_source("windows.registry.hivelist.HiveList",window,cx))))
                        .child(Input::new(&self.registry_key).id("registry-key-path").aria_label("Registry key relative to hive root").small().w(px(350.)))
                        .child(Button::new("registry-open-subkey").small().ghost().label("Open subkey").tooltip("Collect the contents of the selected immediate subkey.").disabled(!child).on_click(cx.listener(|this,_,window,cx| this.browse_registry(true,false,window,cx)))));
            }
            _ => return div(),
        }
        tools
    }

    pub(in crate::ui) fn render_handles(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut content = div().flex().flex_col().gap_2();
        content = content.child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("collect-process-handles")
                        .small()
                        .label("Collect handles for this process")
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.collect_process_handles(window, cx)
                        })),
                )
                .child(
                    Button::new("refresh-process-handles")
                        .small()
                        .ghost()
                        .label("Refresh")
                        .on_click(cx.listener(|this, _, _, cx| this.load_handles(0, cx))),
                ),
        );
        if self.handles_loading {
            return content
                .child("Loading process handles...")
                .into_any_element();
        }
        let Some(page) = &self.handles else {
            return content
                .child("Select a process with a PID to inspect all its handle types.")
                .into_any_element();
        };
        if page.total == 0 {
            return content.child("No handles collected for this PID. Collect handles to load files, registry keys, events, mutexes, sections, processes and other object types.").into_any_element();
        }
        let previous = page.offset.saturating_sub(100);
        let next = page.offset + 100;
        content = content.child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    Button::new("handles-previous")
                        .xsmall()
                        .ghost()
                        .label("Previous")
                        .disabled(page.offset == 0)
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.load_handles(previous, cx)),
                        ),
                )
                .child(format!(
                    "{}..{} of {} handles",
                    page.offset + 1,
                    page.offset + page.records.len(),
                    page.total
                ))
                .child(
                    Button::new("handles-next")
                        .xsmall()
                        .ghost()
                        .label("Next")
                        .disabled(next >= page.total)
                        .on_click(cx.listener(move |this, _, _, cx| this.load_handles(next, cx))),
                ),
        );
        for row in &page.records {
            let id = row.id;
            let text = ["Type", "HandleValue", "GrantedAccess", "FD", "Name", "Path"]
                .iter()
                .filter_map(|key| {
                    row.record
                        .fields
                        .get(*key)
                        .map(|value| format!("{key}: {}", display_value(value)))
                })
                .collect::<Vec<_>>()
                .join("    ");
            content = content.child(
                record_link(key("process-handle", &id.to_string()), text, cx).on_activate(
                    cx.listener(move |this, _, _, cx| {
                        this.detail = DetailTab::Overview;
                        this.load_record(id, cx);
                    }),
                ),
            );
        }
        content.into_any_element()
    }
}
