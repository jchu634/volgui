use super::*;

impl Workspace {
    fn render_sidebar(&self, cx: &mut Context<Self>) -> AnyElement {
        let case = self.case.as_ref().unwrap();
        let mut sidebar = div()
            .id("evidence-sidebar")
            .w(px(252.))
            .flex_shrink_0()
            .h_full()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_4()
            .p_3()
            .border_r_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().sidebar);
        sidebar = sidebar.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(heading("EVIDENCE", cx))
                .child(
                    Button::new("add-evidence")
                        .accessibility_label("Add memory image")
                        .ghost()
                        .xsmall()
                        .icon(IconName::Plus)
                        .tooltip("Add memory image")
                        .disabled(self.busy.is_some())
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.choose_path("evidence", window, cx)
                        })),
                ),
        );
        if case.document.evidence.is_empty() {
            sidebar = sidebar.child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child("No memory images added. Use + to add an acquisition."),
            );
        }
        for evidence in &case.document.evidence {
            let id = evidence.id.clone();
            sidebar = sidebar.child(
                Button::new(key("evidence", &id))
                    .ghost()
                    .small()
                    .w_full()
                    .justify_start()
                    .icon(IconName::HardDrive)
                    .label(evidence.name())
                    .tooltip(evidence.path.display().to_string())
                    .selected(self.selected_evidence.as_ref() == Some(&id))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if !this.save_note(cx) {
                            return;
                        }
                        this.selected_evidence = Some(id.clone());
                        let run = this.case.as_ref().and_then(|c| {
                            c.document
                                .runs
                                .iter()
                                .rev()
                                .find(|r| r.evidence_id == id && r.status == RunStatus::Completed)
                                .map(|r| r.id.clone())
                        });
                        if let Some(run) = run {
                            this.select_run(run, window, cx);
                        } else {
                            this.selected_run = None;
                            this.table = None;
                            this.indexes.clear();
                            this.selected_row = None;
                            this.view = View::Workspace;
                        }
                        cx.notify();
                    })),
            );
        }
        sidebar = sidebar.child(heading("ARTIFACT BROWSER", cx));
        let mut categories = div().flex().flex_col().gap_1();
        for &(name, plugin, ref icon) in CATEGORIES {
            let last_run = case.document.runs.iter().rev().find(|r| {
                r.plugin == plugin
                    && Some(&r.evidence_id) == self.selected_evidence.as_ref()
                    && r.status == RunStatus::Completed
            });
            let label =
                last_run.map_or_else(|| name.to_string(), |r| format!("{name}  {}", r.row_count));
            let active = self
                .selected_run
                .as_ref()
                .is_some_and(|id| last_run.is_some_and(|r| &r.id == id));
            categories = categories.child(
                Button::new(key("category", plugin))
                    .ghost()
                    .small()
                    .w_full()
                    .justify_start()
                    .icon(*icon)
                    .label(label)
                    .selected(active)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.choose_category(plugin, window, cx)
                    })),
            );
        }
        sidebar = sidebar
            .child(heading("WINDOWS SHORTCUTS", cx))
            .child(categories)
            .child(
                Button::new("all-plugins")
                    .small()
                    .ghost()
                    .icon(IconName::Search)
                    .label("Browse all plugins")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Plugins;
                        cx.notify();
                    })),
            );
        let runs: Vec<_> = case
            .document
            .runs
            .iter()
            .rev()
            .filter(|r| Some(&r.evidence_id) == self.selected_evidence.as_ref())
            .take(10)
            .collect();
        if !runs.is_empty() {
            sidebar = sidebar.child(heading("RECENT ANALYSES", cx));
            for run in runs {
                let id = run.id.clone();
                sidebar = sidebar.child(
                    Button::new(key("recent-run", &id))
                        .ghost()
                        .small()
                        .w_full()
                        .justify_start()
                        .label(format!(
                            "{} · {}",
                            run.plugin.split('.').next_back().unwrap_or(&run.plugin),
                            run.status.label()
                        ))
                        .selected(self.selected_run.as_ref() == Some(&id))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.select_run(id.clone(), window, cx)
                        })),
                );
            }
        }
        sidebar.into_any_element()
    }

    fn render_welcome(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div().id("welcome-page").flex_1().overflow_y_scroll().p_8().flex().flex_col().gap_6()
            .child(div().mt_6().text_color(rgb(0xd96b87)).child(Icon::new(IconName::Shield).size_8()))
            .child(heading("VOLGUI / MEMORY FORENSICS",cx))
            .child(div().text_3xl().font_weight(FontWeight::SEMIBOLD).child("An investigation starts with evidence."))
            .child(div().max_w(px(630.)).text_color(cx.theme().muted_foreground)
                .child("Organize memory acquisitions, run Volatility plugins, and keep a traceable record of your findings in a local case."))
            .child(div().flex().gap_3()
                .child(Button::new("welcome-new").primary().icon(IconName::Plus).label("Create a case").disabled(!self.can_switch())
                    .on_click(cx.listener(|this,_,_,cx| { this.view = View::NewCase; cx.notify(); })))
                .child(Button::new("welcome-open").icon(IconName::FolderOpen).label("Open existing case").disabled(!self.can_switch())
                    .on_click(cx.listener(|this,_,window,cx| this.choose_path("open",window,cx)))));
        let (label, description) = if let Some(engine) = &self.installation {
            (
                "Analysis engine connected",
                format!(
                    "{} · {} plugins. Ready to analyze an acquisition.",
                    engine.version,
                    engine.plugins.len()
                ),
            )
        } else {
            ("Connect your analysis engine","Select your separately installed Volatility 3 executable. Its supporting libraries stay in the installation directory.".into())
        };
        page = page.child(
            section(label, cx)
                .max_w(px(760.))
                .child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(description),
                )
                .child(
                    Button::new("welcome-settings")
                        .small()
                        .label("Engine settings")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.view = View::Settings;
                            cx.notify();
                        })),
                ),
        );
        if !self.settings.recent_cases.is_empty() {
            let mut recent = section("Recent cases", cx).max_w(px(760.));
            for (index, path) in self.settings.recent_cases.iter().enumerate() {
                let path = path.clone();
                recent = recent.child(
                    Button::new(("recent-case", index))
                        .ghost()
                        .small()
                        .label(path.parent().unwrap_or(&path).display().to_string())
                        .disabled(!self.can_switch())
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.open_case(path.clone(), window, cx)
                        })),
                );
            }
            page = page.child(recent);
        }
        page.into_any_element()
    }

    fn render_new_case(&self, cx: &mut Context<Self>) -> AnyElement {
        div().id("new-case-page").flex_1().overflow_y_scroll().p_8().child(
            div().max_w(px(720.)).flex().flex_col().gap_5()
                .child(heading("NEW INVESTIGATION",cx))
                .child(div().text_2xl().font_weight(FontWeight::SEMIBOLD).child("Create a case"))
                .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Choose a dedicated directory for the case manifest, analysis output, and annotations. Memory images remain in their original locations."))
                .child(heading("CASE NAME",cx)).child(Input::new(&self.case_name).id("case-name").aria_label("Case name"))
                .child(heading("CASE DIRECTORY",cx))
                .child(div().flex().gap_2().child(Input::new(&self.case_directory).id("case-directory").aria_label("Case directory").flex_1())
                    .child(Button::new("browse-case-directory").label("Browse").on_click(cx.listener(|this,_,window,cx| this.choose_path("directory",window,cx)))))
                .child(Button::new("create-case").primary().label("Create case").disabled(!self.can_switch()).on_click(cx.listener(|this,_,window,cx| this.create_case(window,cx))))
        ).into_any_element()
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div().id("settings-page").flex_1().overflow_y_scroll().p_6().flex().flex_col().gap_5()
            .child(heading("APPLICATION SETTINGS",cx))
            .child(div().text_2xl().font_weight(FontWeight::SEMIBOLD).child("Volatility installation"))
            .child(div().max_w(px(800.)).text_sm().text_color(cx.theme().muted_foreground)
                .child("VolGUI invokes your external Volatility 3 CLI. Select vol.exe or paste its installation directory. Keep all DLLs and support files beside the executable."))
            .child(heading("EXECUTABLE",cx))
            .child(div().flex().gap_2().max_w(px(1000.)).child(Input::new(&self.engine_path).id("engine-path").aria_label("Volatility executable").flex_1())
                .child(Button::new("browse-engine").label("Browse").disabled(self.busy.is_some()).on_click(cx.listener(|this,_,window,cx| this.choose_path("engine",window,cx)))))
            .child(heading("SYMBOLS DIRECTORY",cx))
            .child(div().flex().gap_2().max_w(px(1000.)).child(Input::new(&self.symbol_path).id("symbol-path").aria_label("Symbols directory").flex_1())
                .child(Button::new("browse-symbols").label("Browse").disabled(self.busy.is_some()).on_click(cx.listener(|this,_,window,cx| this.choose_path("symbols",window,cx)))))
            .child(Button::new("offline-mode").label(if self.offline { "Offline mode enabled" } else { "Online symbol lookup enabled" }).selected(self.offline).disabled(self.busy.is_some())
                .on_click(cx.listener(|this,_,_,cx| { this.offline = !this.offline; cx.notify(); })))
            .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Offline mode passes --offline to Volatility. Online mode permits the engine to retrieve missing symbols."))
            .child(Button::new("validate-engine").primary().label("Validate & save installation").disabled(self.busy.is_some() || self.has_queued())
                .on_click(cx.listener(|this,_,_,cx| this.validate_engine(cx))));
        if let Some(engine) = &self.installation {
            page = page.child(
                section("Connected engine", cx)
                    .child(engine.version.clone())
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} discovered plugins · settings saved to {}",
                                engine.plugins.len(),
                                Settings::path().display()
                            )),
                    ),
            );
        }
        page.into_any_element()
    }

    fn render_plugins(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .flex()
            .flex_col()
            .p_5()
            .gap_4()
            .child(heading("ANALYSIS / PLUGIN LIBRARY", cx))
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("New analysis"),
            );
        if self.installation.is_none() {
            return page.child(section("Connect Volatility to discover plugins",cx)
                .child("The plugin catalog is read from your installation, including its Windows, Linux and macOS plugins.")
                .child(Button::new("plugins-settings").label("Configure engine").on_click(cx.listener(|this,_,_,cx| { this.view = View::Settings; cx.notify(); })))).into_any_element();
        }
        let engine = self.installation.as_ref().unwrap();
        page = page.child(
            Input::new(&self.plugin_query)
                .id("plugin-search")
                .aria_label("Search plugins")
                .small()
                .cleanable(true),
        );
        let query = self.plugin_query.read(cx).value().to_lowercase();
        let matching: Vec<_> = engine
            .plugins
            .iter()
            .filter(|p| {
                format!("{} {}", p.id, p.description)
                    .to_lowercase()
                    .contains(&query)
            })
            .collect();
        let mut list = div()
            .id("plugin-list")
            .flex_1()
            .min_w_0()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_1();
        for plugin in matching.iter().take(400) {
            let id = plugin.id.clone();
            list = list.child(
                div()
                    .id(key("plugin", &id))
                    .role(Role::Button)
                    .aria_label(format!("{}: {}", id, plugin.description))
                    .p_3()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(if self.plugin.as_ref() == Some(&id) {
                        cx.theme().accent
                    } else {
                        cx.theme().background
                    })
                    .hover(|s| s.bg(cx.theme().accent))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::MEDIUM)
                            .truncate()
                            .child(id.clone()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(plugin.description.clone()),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.plugin = Some(id.clone());
                        this.plugin_help.clear();
                        cx.notify();
                    })),
            );
        }
        let selected = self
            .plugin
            .as_ref()
            .and_then(|id| engine.plugins.iter().find(|p| &p.id == id));
        let mut setup = div().w(px(390.)).flex_shrink_0().flex().flex_col().gap_3().pl_4().border_l_1().border_color(cx.theme().border)
            .child(heading("CONFIGURE ANALYSIS",cx))
            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(self.plugin.clone().unwrap_or_else(|| "Select a plugin".into())))
            .child(div().text_xs().text_color(cx.theme().muted_foreground).child(self.evidence().map_or_else(|| "Add and select evidence first".into(),|e| format!("Evidence: {}",e.name()))))
            .child(heading("PLUGIN ARGUMENTS",cx))
            .child(Input::new(&self.arguments).id("plugin-arguments").aria_label("Plugin arguments").small())
            .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Use the plugin's CLI options. Quote paths containing spaces. Arguments are passed directly to the executable."))
            .child(div().flex().gap_2()
                .child(Button::new("plugin-options").small().label("Load options").disabled(selected.is_none() || self.busy.is_some()).on_click(cx.listener(|this,_,_,cx| this.plugin_help(cx))))
                .child(Button::new("queue-analysis").small().primary().icon(IconName::Play).label("Queue analysis")
                    .disabled(selected.is_none() || self.evidence().is_none() || self.busy.as_ref().is_some_and(|b| b.run_id.is_none()))
                    .on_click(cx.listener(|this,_,window,cx| this.queue_analysis(window,cx)))));
        if !self.plugin_help.is_empty() {
            setup = setup.child(
                div()
                    .id("plugin-help")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_3()
                    .bg(cx.theme().muted)
                    .rounded_md()
                    .text_xs()
                    .font_family("Consolas")
                    .child(self.plugin_help.clone()),
            );
        }
        page.child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{} plugins match · {} installed",
                    matching.len(),
                    engine.plugins.len()
                )),
        )
        .child(
            div()
                .flex()
                .flex_1()
                .min_h_0()
                .gap_4()
                .child(list)
                .child(setup),
        )
        .into_any_element()
    }

    fn render_analyses(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div().id("analysis-history").flex_1().overflow_y_scroll().p_5().flex().flex_col().gap_4()
            .child(heading("CASE / ANALYSIS HISTORY",cx))
            .child(div().text_2xl().font_weight(FontWeight::SEMIBOLD).child("Analyses"))
            .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Jobs run one at a time. Commands, diagnostics and generated files are retained in the case directory."));
        let Some(case) = &self.case else {
            return page
                .child("Open a case to run analyses.")
                .into_any_element();
        };
        if self.queue_paused {
            page = page.child(
                Button::new("resume-queue")
                    .label("Retry save & resume queue")
                    .on_click(cx.listener(|this, _, _, cx| {
                        let result = this.case.as_mut().map(|c| c.save());
                        if let Some(Err(error)) = result {
                            this.error = Some(error);
                        } else {
                            this.queue_paused = false;
                            this.error = None;
                        }
                        cx.notify();
                    })),
            );
        }
        if case.document.runs.is_empty() {
            page = page.child(section("No analyses yet", cx).child(
                "Add a memory image, then choose New analysis to explore the installed plugins.",
            ));
        }
        for run in case.document.runs.iter().rev() {
            let id = run.id.clone();
            let cancel_id = id.clone();
            let rerun_id = id.clone();
            let evidence = case
                .document
                .evidence
                .iter()
                .find(|e| e.id == run.evidence_id)
                .map(|e| e.name())
                .unwrap_or_default();
            let mut actions = div().flex().gap_2().child(
                Button::new(key("view-run", &id))
                    .small()
                    .label("Inspect")
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_run(id.clone(), window, cx)
                    })),
            );
            if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                actions = actions.child(
                    Button::new(key("cancel-run", &cancel_id))
                        .small()
                        .label("Cancel")
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.cancel_run(cancel_id.clone(), cx)
                        })),
                );
            } else {
                actions = actions.child(
                    Button::new(key("rerun", &rerun_id))
                        .small()
                        .label("Rerun setup")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(run) = this
                                .case
                                .as_ref()
                                .and_then(|c| c.document.runs.iter().find(|r| r.id == rerun_id))
                                .cloned()
                            {
                                this.plugin = Some(run.plugin);
                                this.selected_evidence = Some(run.evidence_id);
                                this.plugin_help.clear();
                                let args = format_arguments(&run.arguments);
                                this.arguments
                                    .update(cx, |state, cx| state.set_value(args, window, cx));
                                this.view = View::Plugins;
                                cx.notify();
                            }
                        })),
                );
            }
            page = page.child(
                section(run.plugin.clone(), cx)
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .gap_4()
                            .child(div().text_sm().child(format!(
                                "{} · {} rows · {}",
                                run.status.label(),
                                run.row_count,
                                evidence
                            )))
                            .child(actions),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{} · {}", run.created_at, run.engine_version)),
                    )
                    .when(
                        !run.message.is_empty() && run.status != RunStatus::Completed,
                        |s| {
                            s.child(
                                div()
                                    .text_xs()
                                    .child(run.message.chars().take(500).collect::<String>()),
                            )
                        },
                    ),
            );
        }
        page.into_any_element()
    }

    fn render_bookmarks(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("bookmarks-page")
            .flex_1()
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(heading("CASE / FINDINGS", cx))
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Bookmarks & notes"),
            );
        let Some(case) = &self.case else {
            return page.into_any_element();
        };
        if case.document.annotations.is_empty() {
            page = page.child("Select an artifact to bookmark it or write an observation.");
        }
        for (index, a) in case.document.annotations.iter().enumerate() {
            let id = a.run_id.clone();
            let row = a.row;
            let plugin = case
                .document
                .runs
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.plugin.clone())
                .unwrap_or_default();
            page = page.child(
                section(
                    format!(
                        "{} · artifact {}{}",
                        plugin,
                        row + 1,
                        if a.bookmarked { " · bookmarked" } else { "" }
                    ),
                    cx,
                )
                .child(div().text_sm().child(if a.note.is_empty() {
                    "No observation added".into()
                } else {
                    a.note.clone()
                }))
                .child(
                    Button::new(("open-bookmark", index))
                        .small()
                        .label("Open artifact")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.select_run(id.clone(), window, cx);
                            if this.table.is_some() {
                                this.select_row(Some(row), window, cx);
                                this.page =
                                    this.indexes.iter().position(|i| *i == row).unwrap_or(0)
                                        / PAGE_SIZE;
                            } else {
                                this.pending_row = Some((id.clone(), row));
                            }
                        })),
                ),
            );
        }
        page.into_any_element()
    }

    fn render_case_info(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("case-info-page")
            .flex_1()
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(heading("CASE / EVIDENCE REGISTER", cx));
        let Some(case) = &self.case else {
            return page.into_any_element();
        };
        page = page
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(case.document.name.clone()),
            )
            .child(div().text_sm().child(format!(
                "Created {} · {} evidence file(s) · {} analyses",
                case.document.created_at,
                case.document.evidence.len(),
                case.document.runs.len()
            )))
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(case.directory.display().to_string()),
            )
            .child(
                Button::new("case-report")
                    .small()
                    .label("Export case report")
                    .on_click(cx.listener(|this, _, window, cx| this.export(true, window, cx))),
            );
        for evidence in &case.document.evidence {
            let id = evidence.id.clone();
            page = page.child(
                section(evidence.name(), cx)
                    .child(div().text_sm().child(evidence.path.display().to_string()))
                    .child(div().text_xs().child(format!(
                        "{} · added {}",
                        format_bytes(evidence.size),
                        evidence.added_at
                    )))
                    .child(heading("SHA-256 AT IMPORT", cx))
                    .child(
                        div()
                            .text_xs()
                            .font_family("Consolas")
                            .child(evidence.sha256.clone()),
                    )
                    .when_some(evidence.verification.as_ref(), |s, v| {
                        s.child(div().text_xs().child(format!(
                            "Last verification {} · {}",
                            v.checked_at,
                            if v.matches { "MATCH" } else { "MISMATCH" }
                        )))
                    })
                    .child(
                        Button::new(key("verify", &id))
                            .small()
                            .label("Verify integrity")
                            .disabled(self.busy.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected_evidence = Some(id.clone());
                                this.verify(cx);
                            })),
                    ),
            );
        }
        page.into_any_element()
    }
}

impl Workspace {
    fn render_workspace(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div().flex_1().min_w_0().min_h_0().flex().flex_col();
        let run = self.case.as_ref().and_then(|c| {
            c.document
                .runs
                .iter()
                .find(|r| Some(&r.id) == self.selected_run.as_ref())
        });
        let record = self
            .table
            .as_ref()
            .and_then(|t| self.selected_row.and_then(|row| t.rows.get(row)));
        let bookmarked = self
            .case
            .as_ref()
            .and_then(|c| c.annotation(self.selected_run.as_deref()?, self.selected_row?))
            .is_some_and(|a| a.bookmarked);
        let title = record.map(|r| r.title()).unwrap_or_else(|| {
            if run.is_some() {
                "Analysis results".into()
            } else {
                "Evidence workspace".into()
            }
        });
        let mut header = div()
            .p_5()
            .flex()
            .flex_col()
            .gap_2()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(heading(
                run.map(|r| r.plugin.to_uppercase())
                    .unwrap_or_else(|| "INVESTIGATION WORKSPACE".into()),
                cx,
            ))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .text_2xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .when(record.is_some(), |s| {
                        s.child(
                            Button::new("bookmark-artifact")
                                .small()
                                .icon(IconName::Bookmark)
                                .label(if bookmarked { "Bookmarked" } else { "Bookmark" })
                                .selected(bookmarked)
                                .on_click(cx.listener(|this, _, _, cx| this.annotate(true, cx))),
                        )
                    }),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.evidence().map_or_else(
                        || "No acquisition selected".into(),
                        |e| format!("{} · {} · SHA-256 recorded", e.name(), format_bytes(e.size)),
                    )),
            );
        if run.is_some() {
            let mut tabs = div().flex().gap_1().mt_2();
            for (id, label, tab) in [
                ("overview", "Overview", DetailTab::Overview),
                ("raw", "Raw JSON", DetailTab::Raw),
                ("notes", "Notes", DetailTab::Notes),
                ("diagnostics", "Run details", DetailTab::Diagnostics),
            ] {
                tabs = tabs.child(
                    Button::new(id)
                        .small()
                        .ghost()
                        .label(label)
                        .selected(self.detail == tab)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.detail = tab;
                            cx.notify();
                        })),
                );
            }
            header = header.child(tabs);
        }
        page = page.child(header);
        if self.selected_run.is_none() {
            let has_evidence = self.evidence().is_some();
            return page.child(div().flex_1().p_8().flex().flex_col().gap_4()
                .child(div().text_lg().font_weight(FontWeight::SEMIBOLD).child(if has_evidence { "Ready to examine this acquisition" } else { "Add your first memory image" }))
                .child(div().max_w(px(650.)).text_sm().text_color(cx.theme().muted_foreground).child(if has_evidence {
                    "Start with system information and process enumeration, then examine network connections, files or registry artifacts. Every run is saved with its original output."
                } else { "Choose an acquired memory image. VolGUI will record its size and SHA-256 before adding it to this case." }))
                .child(Button::new("workspace-start").primary().label(if has_evidence { "Choose an analysis" } else { "Add memory image" })
                    .disabled(self.busy.is_some()).on_click(cx.listener(move |this,_,window,cx| { if has_evidence { this.view = View::Plugins; } else { this.choose_path("evidence",window,cx); } cx.notify(); })))
            ).into_any_element();
        }
        let mut detail = div()
            .id("artifact-detail")
            .flex_1()
            .min_h(px(100.))
            .overflow_y_scroll()
            .p_5();
        match self.detail {
            DetailTab::Overview => {
                if let Some(record) = record {
                    let mut fields = div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(heading("RECOVERED FIELDS", cx));
                    for (index, (name, value)) in record.fields.iter().enumerate() {
                        fields = fields.child(
                            div()
                                .id(("field", index))
                                .flex()
                                .gap_4()
                                .py_2()
                                .border_b_1()
                                .border_color(cx.theme().border)
                                .child(
                                    div()
                                        .w(px(190.))
                                        .flex_shrink_0()
                                        .text_xs()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(name.clone()),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .text_sm()
                                        .child(display_value(value)),
                                ),
                        );
                    }
                    detail = detail.child(fields);
                } else {
                    detail = detail.child(
                        section(
                            if self.loading.is_some() {
                                "Loading saved results..."
                            } else {
                                "No artifact selected"
                            },
                            cx,
                        )
                        .child(run.map_or_else(
                            || "Select a result row below".into(),
                            |r| {
                                format!(
                                    "{} · {} records. {}",
                                    r.status.label(),
                                    r.row_count,
                                    if r.status == RunStatus::Completed {
                                        "The plugin returned no records, or no row is selected."
                                    } else {
                                        "Open Run details for diagnostics."
                                    }
                                )
                            },
                        )),
                    );
                }
            }
            DetailTab::Raw => {
                detail = detail.child(
                    div().text_xs().font_family("Consolas").child(
                        record
                            .map(|r| serde_json::to_string_pretty(&r.fields).unwrap_or_default())
                            .unwrap_or_else(|| {
                                "Select an artifact to inspect its raw fields.".into()
                            }),
                    ),
                );
            }
            DetailTab::Notes => {
                detail = detail.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(heading("INVESTIGATOR OBSERVATIONS", cx))
                        .child(
                            Textarea::new(&self.note)
                                .accessibility_id("artifact-note")
                                .h(px(130.)),
                        )
                        .child(
                            Button::new("save-note")
                                .small()
                                .primary()
                                .label("Save note")
                                .disabled(record.is_none())
                                .on_click(cx.listener(|this, _, _, cx| this.annotate(false, cx))),
                        ),
                );
            }
            DetailTab::Diagnostics => {
                if let Some(run) = run {
                    let output = self.case.as_ref().unwrap().run_dir(&run.id);
                    detail = detail.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(heading(
                                format!(
                                    "{} · EXIT {:?} · {} ROWS",
                                    run.status.label().to_uppercase(),
                                    run.exit_code,
                                    run.row_count
                                ),
                                cx,
                            ))
                            .child(div().text_xs().child(format!(
                                "{}\nQueued {}\nStarted {}\nFinished {}\nRun {}",
                                run.engine_version,
                                run.created_at,
                                run.started_at.as_deref().unwrap_or("Not started"),
                                run.finished_at.as_deref().unwrap_or("Not finished"),
                                run.id
                            )))
                            .child(heading("COMMAND ARGUMENT VECTOR", cx))
                            .child(div().text_xs().font_family("Consolas").child(
                                serde_json::to_string_pretty(&run.command).unwrap_or_default(),
                            ))
                            .child(
                                Button::new("reveal-output")
                                    .small()
                                    .label("Show output directory")
                                    .on_click(move |_, _, cx| cx.reveal_path(&output)),
                            )
                            .child(heading("DIAGNOSTICS", cx))
                            .child(div().text_xs().font_family("Consolas").child(
                                if run.message.is_empty() {
                                    "No diagnostics recorded".into()
                                } else {
                                    run.message.clone()
                                },
                            )),
                    );
                }
            }
        }
        page.child(detail)
            .child(self.render_results(cx))
            .into_any_element()
    }

    fn render_results(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(table) = &self.table else {
            return div().into_any_element();
        };
        let mut panel = div()
            .h(px(290.))
            .flex_shrink_0()
            .min_w_0()
            .flex()
            .flex_col()
            .border_t_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py_2()
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_sm()
                            .child("Artifact results"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} matched / {} total",
                                self.indexes.len(),
                                table.rows.len()
                            )),
                    )
                    .child(
                        div().ml_auto().w(px(300.)).child(
                            Input::new(&self.query)
                                .id("result-search")
                                .aria_label("Search artifacts")
                                .small()
                                .cleanable(true),
                        ),
                    )
                    .child(
                        Button::new("export-csv")
                            .small()
                            .ghost()
                            .label("Export CSV")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.export(false, window, cx)),
                            ),
                    ),
            );
        let width = table.columns.len().max(1) as f32 * 160.;
        let mut grid = div()
            .id("result-list")
            .role(Role::ListBox)
            .aria_label("Artifact results")
            .w(px(width))
            .min_w_full()
            .flex()
            .flex_col();
        let mut header = div()
            .flex()
            .h_8()
            .flex_shrink_0()
            .bg(cx.theme().muted)
            .items_center();
        for (index, column) in table.columns.iter().enumerate() {
            let column = column.clone();
            let suffix = self
                .sort
                .as_ref()
                .filter(|(c, _)| c == &column)
                .map_or("", |(_, d)| if *d { " ↓" } else { " ↑" });
            header = header.child(
                div()
                    .id(("sort", index))
                    .w(px(160.))
                    .min_w(px(160.))
                    .flex_1()
                    .px_3()
                    .text_xs()
                    .font_weight(FontWeight::SEMIBOLD)
                    .cursor_pointer()
                    .child(format!("{column}{suffix}"))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let descending =
                            this.sort.as_ref().is_some_and(|(c, d)| c == &column && !d);
                        this.sort = Some((column.clone(), descending));
                        this.page = 0;
                        this.refilter(cx);
                        cx.notify();
                    })),
            );
        }
        grid = grid.child(header);
        for &index in self
            .indexes
            .iter()
            .skip(self.page * PAGE_SIZE)
            .take(PAGE_SIZE)
        {
            let record = &table.rows[index];
            let mut row =
                div()
                    .id(("result-row", index))
                    .role(Role::ListBoxOption)
                    .aria_label(format!("Artifact {}: {}", index + 1, record.title()))
                    .aria_selected(self.selected_row == Some(index))
                    .flex()
                    .items_center()
                    .h_8()
                    .flex_shrink_0()
                    .cursor_pointer()
                    .bg(if self.selected_row == Some(index) {
                        cx.theme().accent
                    } else {
                        cx.theme().background
                    })
                    .hover(|s| s.bg(cx.theme().muted))
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_row(Some(index), window, cx)
                    }));
            for (col, column) in table.columns.iter().enumerate() {
                row = row.child(
                    div()
                        .w(px(160.))
                        .min_w(px(160.))
                        .flex_1()
                        .px_3()
                        .text_xs()
                        .truncate()
                        .when(col == 0, |s| {
                            s.pl(px(12. + record.depth.min(6) as f32 * 10.))
                        })
                        .child(record.text(column)),
                );
            }
            grid = grid.child(row);
        }
        if self.indexes.is_empty() {
            grid = grid.child(
                div()
                    .p_4()
                    .text_sm()
                    .child("No artifacts match this search."),
            );
        }
        panel = panel.child(
            div()
                .id("results-scroll")
                .flex_1()
                .min_h_0()
                .overflow_scroll()
                .child(grid),
        );
        let pages = self.indexes.len().div_ceil(PAGE_SIZE).max(1);
        panel
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_4()
                    .py_1()
                    .text_xs()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(format!(
                        "Page {} of {pages} · click a column to sort",
                        self.page + 1
                    ))
                    .child(
                        div()
                            .flex()
                            .gap_1()
                            .child(
                                Button::new("previous-page")
                                    .xsmall()
                                    .ghost()
                                    .label("Previous")
                                    .disabled(self.page == 0)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.page = this.page.saturating_sub(1);
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("next-page")
                                    .xsmall()
                                    .ghost()
                                    .label("Next")
                                    .disabled(self.page + 1 >= pages)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.page += 1;
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .into_any_element()
    }
}

impl Render for Workspace {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let case_open = self.case.is_some();
        let case_name = self
            .case
            .as_ref()
            .map(|c| c.document.name.clone())
            .unwrap_or_else(|| "No case open".into());
        let title = TitleBar::new().child(
            div()
                .flex()
                .flex_1()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .text_color(rgb(0xd96b87))
                        .child(Icon::new(IconName::Shield).size_4()),
                )
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_sm()
                        .child("volgui"),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child("MEMORY FORENSICS"),
                )
                .child(div().ml_auto().mr_3().text_xs().child(case_name)),
        );
        let toolbar = div()
            .flex()
            .flex_shrink_0()
            .items_center()
            .px_3()
            .py_2()
            .gap_2()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                Button::new("new-case")
                    .small()
                    .ghost()
                    .label("New case")
                    .disabled(!self.can_switch() || self.has_queued())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::NewCase;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("open-case")
                    .small()
                    .ghost()
                    .label("Open case")
                    .disabled(!self.can_switch() || self.has_queued())
                    .on_click(
                        cx.listener(|this, _, window, cx| this.choose_path("open", window, cx)),
                    ),
            )
            .child(div().w_px().h_4().mx_1().bg(cx.theme().border))
            .child(
                Button::new("nav-workspace")
                    .small()
                    .ghost()
                    .label("Workspace")
                    .selected(self.view == View::Workspace)
                    .disabled(!case_open)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Workspace;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("nav-analyses")
                    .small()
                    .ghost()
                    .label("Analyses")
                    .selected(self.view == View::Analyses)
                    .disabled(!case_open)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Analyses;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("nav-bookmarks")
                    .small()
                    .ghost()
                    .label("Bookmarks")
                    .selected(self.view == View::Bookmarks)
                    .disabled(!case_open)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Bookmarks;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("nav-case")
                    .small()
                    .ghost()
                    .label("Case info")
                    .selected(self.view == View::CaseInfo)
                    .disabled(!case_open)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::CaseInfo;
                        cx.notify();
                    })),
            )
            .child(div().ml_auto())
            .child(
                Button::new("new-analysis")
                    .small()
                    .primary()
                    .icon(IconName::Plus)
                    .label("New analysis")
                    .disabled(!case_open)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Plugins;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("settings")
                    .accessibility_label("Application settings")
                    .small()
                    .ghost()
                    .icon(IconName::Settings)
                    .tooltip("Application settings")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.view = View::Settings;
                        cx.notify();
                    })),
            );
        let content = match self.view {
            View::Welcome => self.render_welcome(cx),
            View::NewCase => self.render_new_case(cx),
            View::Settings => self.render_settings(cx),
            View::Plugins => self.render_plugins(cx),
            View::Analyses => self.render_analyses(cx),
            View::Bookmarks => self.render_bookmarks(cx),
            View::CaseInfo => self.render_case_info(cx),
            View::Workspace => self.render_workspace(cx),
        };
        let body = div()
            .flex()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .when(self.sidebar_visible && case_open, |s| {
                s.child(self.render_sidebar(cx))
            })
            .child(content);
        let queued = self.case.as_ref().map_or(0, |c| {
            c.document
                .runs
                .iter()
                .filter(|r| r.status == RunStatus::Queued)
                .count()
        });
        let status = div()
            .flex()
            .flex_shrink_0()
            .h_8()
            .items_center()
            .px_3()
            .gap_3()
            .border_t_1()
            .border_color(cx.theme().border)
            .text_xs()
            .child(
                Button::new("toggle-sidebar")
                    .accessibility_label("Toggle evidence sidebar")
                    .xsmall()
                    .ghost()
                    .icon(IconName::PanelLeft)
                    .tooltip("Toggle evidence sidebar")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.sidebar_visible = !this.sidebar_visible;
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.message.clone()),
            )
            .when_some(self.busy.as_ref(), |s, busy| {
                s.child(div().text_color(rgb(0xd96b87)).child(format!(
                    "{} · {}s",
                    busy.label,
                    busy.started.elapsed().as_secs()
                )))
                .child(
                    Button::new("cancel-background")
                        .xsmall()
                        .ghost()
                        .label("Cancel")
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let Some(busy) = &this.busy {
                                busy.cancel.store(true, Ordering::Relaxed);
                                this.message = "Cancelling...".into();
                            }
                            cx.notify();
                        })),
                )
            })
            .child(format!("{queued} queued"));
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(title)
            .child(toolbar)
            .when_some(self.error.clone(), |s, error| {
                s.child(
                    div()
                        .flex()
                        .items_start()
                        .gap_3()
                        .px_4()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .bg(rgb(0x321d25))
                        .child(
                            div()
                                .id("error-message")
                                .flex_1()
                                .max_h(px(100.))
                                .overflow_y_scroll()
                                .text_xs()
                                .child(error),
                        )
                        .child(
                            Button::new("dismiss-error")
                                .xsmall()
                                .ghost()
                                .label("Dismiss")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.error = None;
                                    cx.notify();
                                })),
                        ),
                )
            })
            .child(body)
            .child(status)
    }
}
