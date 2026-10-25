use super::*;

impl Workspace {
    pub(in crate::ui) fn render_investigation_tools(&self, cx: &mut Context<Self>) -> Div {
        let mut tools = div().flex().flex_col().gap_2().px_3().py_2();
        match self.result_group() {
            Some(ArtifactGroup::Web) => {
                tools = tools.child(div().text_xs().child("Collect browser processes, then recover browser memory to find Edge, Firefox and Tor URLs and searches with their PID. Search the results for a phrase, domain or PID. Memory findings can include stale strings, resources and suggestions; they do not alone prove a visit. Process dumps are saved in the case and can use several GB."))
                    .child(div().flex().flex_wrap().gap_2()
                        .child(Button::new("collect-browser-processes").small().ghost().label("Collect browser processes").disabled(self.busy.is_some() || self.installation.is_none()).on_click(cx.listener(|this,_,window,cx| this.collect_browser_processes(window,cx))))
                        .child(Button::new("recover-browser-memory").small().label("Recover browser memory").disabled(self.busy.is_some() || self.installation.is_none()).on_click(cx.listener(|this,_,_,cx| this.recover_browser_memory(cx)))))
                    .child(div().text_xs().child("For recorded history and saved tabs, scan for files or collect Process handles, then recover profile files. File handle PIDs identify file owners. Session tabs describe the saved snapshot."))
                    .child(div().flex().flex_wrap().gap_2()
                        .child(Button::new("collect-browser-file-scan").small().ghost().label("Scan for files").disabled(self.installation.is_none()).on_click(cx.listener(|this,_,window,cx| this.collect_source("windows.filescan.FileScan",window,cx))))
                        .child(Button::new("recover-browser").small().label("Recover profile files").disabled(self.busy.is_some() || self.installation.is_none()).on_click(cx.listener(|this,_,window,cx| this.analyze_browser(true,window,cx))))
                        .child(Button::new("analyze-browser-files").small().ghost().label("Analyze recovered data").disabled(self.busy.as_ref().is_some_and(|b| b.run_id.is_none())).on_click(cx.listener(|this,_,window,cx| this.analyze_browser(false,window,cx))))
                        .child(Button::new("browser-offset-space").small().ghost().label(if self.file_offset_physical { "FileScan: physical offsets" } else { "FileScan: virtual offsets" }).tooltip("Unlabelled FileScan offsets use virtual memory on Windows 10+, physical memory on older captures.").on_click(cx.listener(|this,_,_,cx| { this.file_offset_physical = !this.file_offset_physical; cx.notify(); }))));
            }
            Some(ArtifactGroup::Strings) => {
                tools = tools.child(div().text_xs().child("Search the selected evidence file for a literal string in UTF-8, UTF-16LE and UTF-16BE. Results include byte offsets and context. Maximum 10,000 matches per analysis."))
                    .child(div().flex().items_center().gap_2()
                        .child(Input::new(&self.string_needle).id("global-string-needle").aria_label("String to find in evidence").small().w(px(360.)))
                        .child(Checkbox::new("string-ignore-case").label("Ignore ASCII case").checked(self.string_ignore_case).on_click(cx.listener(|this,checked,_,cx| { this.string_ignore_case = *checked; cx.notify(); })))
                        .child(Button::new("run-global-search").small().label("Search evidence").disabled(self.evidence().is_none() || self.busy.as_ref().is_some_and(|b| b.run_id.is_none())).on_click(cx.listener(|this,_,window,cx| this.run_string_search(window,cx)))));
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
                        volgui::investigation::registry::child_key(run, &r.record)
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
