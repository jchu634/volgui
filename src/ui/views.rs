use super::*;
use gpui_kit::component::dialog::DialogButtonProps;

#[derive(Clone)]
enum FileCommand {
    New,
    Open,
    Recent(PathBuf),
    Evidence,
    Settings,
    Close,
}
impl Workspace {
    fn file_item(
        label: impl Into<SharedString>,
        command: FileCommand,
        disabled: bool,
        weak: WeakEntity<Self>,
    ) -> PopupMenuItem {
        PopupMenuItem::new(label)
            .disabled(disabled)
            .on_click(move |_, window, cx| {
                let _ = weak.update(cx, |this, cx| match &command {
                    FileCommand::New => {
                        if this.can_switch() {
                            this.navigate(View::NewCase, cx);
                        }
                    }
                    FileCommand::Open => this.choose_path("open", window, cx),
                    FileCommand::Recent(path) => this.open_case(path.clone(), window, cx),
                    FileCommand::Evidence => this.choose_path("evidence", window, cx),
                    FileCommand::Settings => this.open_settings(window, cx),
                    FileCommand::Close => this.close_case(window, cx),
                });
            })
    }
    fn file_menu(
        weak: WeakEntity<Self>,
        menu: PopupMenu,
        window: &mut Window,
        cx: &mut Context<PopupMenu>,
    ) -> PopupMenu {
        let Some(workspace) = weak.upgrade() else {
            return menu;
        };
        let ws = workspace.read(cx);
        let disabled = !ws.can_switch();
        let recent = ws.settings.recent_cases.clone();
        let evidence_disabled = ws.case.is_none() || ws.busy.is_some();
        let close_disabled = ws.case.is_none() || disabled;
        let mut menu = menu
            .item(Self::file_item(
                "New case",
                FileCommand::New,
                disabled,
                weak.clone(),
            ))
            .item(Self::file_item(
                "Open case...",
                FileCommand::Open,
                disabled,
                weak.clone(),
            ));
        let recent_weak = weak.clone();
        menu = menu.submenu("Recent cases", window, cx, move |mut menu, _, _| {
            if recent.is_empty() {
                return menu.label("No recent cases");
            }
            for path in &recent {
                menu = menu.item(Self::file_item(
                    path.parent()
                        .unwrap_or(path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    FileCommand::Recent(path.clone()),
                    disabled,
                    recent_weak.clone(),
                ));
            }
            menu
        });
        menu.item(Self::file_item(
            "Close case",
            FileCommand::Close,
            close_disabled,
            weak.clone(),
        ))
        .separator()
        .item(Self::file_item(
            "Add evidence...",
            FileCommand::Evidence,
            evidence_disabled,
            weak.clone(),
        ))
        .separator()
        .item(Self::file_item(
            "Settings...",
            FileCommand::Settings,
            false,
            weak,
        ))
    }
    fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let workspace = cx.entity().downgrade();
        let panel = cx.new(|cx| {
            let subscription = cx.observe(&workspace.upgrade().unwrap(), |_, _, cx| cx.notify());
            SettingsPanel {
                workspace: workspace.clone(),
                _subscription: subscription,
            }
        });
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .title("Settings")
                .width(px(720.))
                .button_props(DialogButtonProps::default().ok_text("Close"))
                .child(panel.clone())
        });
    }
    fn render_settings_content(&self, cx: &mut Context<Self>) -> AnyElement {
        div().flex().flex_col().gap_3().w_full()
            .child(heading("VOLATILITY INSTALLATION",cx))
            .child(div().text_sm().child("Select the separately installed CLI. Its supporting files stay beside the executable."))
            .child(heading("Executable",cx)).child(div().flex().gap_2().child(Input::new(&self.engine_path).id("engine-path").aria_label("Volatility executable").flex_1()).child(Button::new("browse-engine").small().label("Browse").disabled(self.busy.is_some()).on_click(cx.listener(|this,_,window,cx|this.choose_path("engine",window,cx)))))
            .child(heading("Symbols directory",cx)).child(div().flex().gap_2().child(Input::new(&self.symbol_path).id("symbol-path").aria_label("Symbols directory").flex_1()).child(Button::new("browse-symbols").small().label("Browse").disabled(self.busy.is_some()).on_click(cx.listener(|this,_,window,cx|this.choose_path("symbols",window,cx)))))
            .child(Button::new("offline-mode").small().label(if self.offline{"Offline mode enabled"}else{"Online symbol lookup enabled"}).selected(self.offline).disabled(self.busy.is_some()).on_click(cx.listener(|this,_,_,cx|{this.offline = !this.offline;cx.notify();})))
            .child(div().flex().gap_2().child(Button::new("validate-engine").small().primary().label("Validate and save").disabled(self.busy.is_some()||self.has_queued()).on_click(cx.listener(|this,_,_,cx|this.validate_engine(cx))))
                .when(self.busy.as_ref().is_some_and(|b|b.run_id.is_none()),|s|s.child(Button::new("cancel-settings-job").small().label("Cancel check").on_click(cx.listener(|this,_,_,cx|{if let Some(b)=&this.busy{b.cancel.store(true,Ordering::Relaxed);}cx.notify();})))))
            .when_some(self.installation.as_ref(),|s,e|s.child(div().text_xs().text_color(cx.theme().muted_foreground).child(format!("{} · {} plugins",e.version,e.plugins.len()))))
            .when_some(self.error.clone(),|s,e|s.child(div().text_sm().text_color(cx.theme().danger).child(e)))
            .into_any_element()
    }
    pub(super) fn group_icon(group: ArtifactGroup) -> IconName {
        match group {
            ArtifactGroup::Processes => IconName::Cpu,
            ArtifactGroup::Network => IconName::Network,
            ArtifactGroup::Files => IconName::Folder,
            ArtifactGroup::Registry => IconName::Database,
            ArtifactGroup::Memory => IconName::Shield,
            ArtifactGroup::System => IconName::Info,
            ArtifactGroup::Commands => IconName::Terminal,
            ArtifactGroup::Modules => IconName::Layers,
            ArtifactGroup::Sessions => IconName::Users,
            ArtifactGroup::Other => IconName::Archive,
        }
    }
    fn render_sidebar(&self, cx: &mut Context<Self>) -> AnyElement {
        let case = self.case.as_ref().unwrap();
        let mut evidence = div()
            .id("evidence-list")
            .max_h(px(112.))
            .overflow_y_scroll()
            .flex()
            .flex_col();
        for image in &case.document.evidence {
            let id = image.id.clone();
            evidence = evidence.child(
                ListItem::new(key("evidence", &id))
                    .role(Role::Button)
                    .h(px(32.))
                    .selected(self.selected_evidence.as_ref() == Some(&id))
                    .accessibility_label(image.name())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .w_full()
                            .child(Icon::new(IconName::HardDrive).size_4())
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_sm()
                                    .truncate()
                                    .child(image.name()),
                            ),
                    )
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_evidence(id.clone(), window, cx)
                    })),
            );
        }
        let mut tabs = div().flex().gap_1();
        for group in ArtifactGroup::BROWSER {
            let label = if group == ArtifactGroup::Files {
                "Files"
            } else {
                group.label()
            };
            tabs = tabs.child(
                Button::new(key("browser", label))
                    .small()
                    .ghost()
                    .icon(Self::group_icon(group))
                    .label(label)
                    .flex_1()
                    .selected(self.browser_group == group)
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.set_browser(group, window, cx)),
                    ),
            );
        }
        let mut mode = div().flex().items_center().gap_1().child(
            div()
                .flex_1()
                .text_xs()
                .child(format!("{} items", self.browser_entries.len())),
        );
        if self.browser_group == ArtifactGroup::Processes {
            for (id, label, value) in [("tree", "Tree", true), ("list", "List", false)] {
                mode = mode.child(
                    Button::new(id)
                        .xsmall()
                        .ghost()
                        .label(label)
                        .selected(self.browser_tree_mode == value)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.browser_tree_mode = value;
                            cx.notify();
                        })),
                );
            }
        }
        let browser = if self.browser_loading {
            div()
                .p_2()
                .text_xs()
                .child("Loading artifacts...")
                .into_any_element()
        } else if self.browser_entries.is_empty() {
            div()
                .p_2()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child("No matching scan data. Run an analysis to populate this browser.")
                .into_any_element()
        } else if self.browser_group == ArtifactGroup::Processes && self.browser_tree_mode {
            Tree::new(&self.browser_tree, move |ix, entry, _, _, _| {
                ListItem::new(("process-node", ix))
                    .h(px(30.))
                    .accessibility_label(entry.item().label.clone())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .w_full()
                            .pl(px(entry.depth().min(30) as f32 * 12.))
                            .when(entry.is_folder(), |s| {
                                s.child(
                                    Icon::new(if entry.is_expanded() {
                                        IconName::ChevronDown
                                    } else {
                                        IconName::ChevronRight
                                    })
                                    .size_3(),
                                )
                            })
                            .when(!entry.is_folder(), |s| s.child(div().w_3()))
                            .child(Icon::new(IconName::Cpu).size_3())
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_xs()
                                    .truncate()
                                    .child(entry.item().label.clone()),
                            ),
                    )
            })
            .into_any_element()
        } else {
            let list = v_virtual_list(
                cx.entity(),
                "artifact-virtual-list",
                self.browser_sizes.clone(),
                |this, range, _, cx| {
                    range
                        .map(|i| {
                            let entry = &this.browser_entries[i];
                            let id = entry.id;
                            ListItem::new(("browser-record", id as u64))
                                .w(px(680.))
                                .role(Role::Button)
                                .h(px(30.))
                                .selected(this.selected.as_ref().is_some_and(|r| r.id == id))
                                .accessibility_label(entry.title.clone())
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .w_full()
                                        .child(
                                            Icon::new(Self::group_icon(this.browser_group))
                                                .size_3(),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .text_xs()
                                                .truncate()
                                                .child(entry.title.clone()),
                                        ),
                                )
                                .on_click(
                                    cx.listener(move |this, _, _, cx| this.load_record(id, cx)),
                                )
                        })
                        .collect::<Vec<_>>()
                },
            )
            .track_scroll(&self.browser_scroll)
            .w_full()
            .h_full();
            div()
                .relative()
                .size_full()
                .pb(px(12.))
                .child(list)
                .child(
                    Scrollbar::vertical(self.browser_scroll.base_handle())
                        .mode(ScrollbarMode::Always),
                )
                .child(
                    Scrollbar::horizontal(self.browser_scroll.base_handle())
                        .mode(ScrollbarMode::Always),
                )
                .into_any_element()
        };
        let mut shortcuts = div()
            .flex()
            .flex_col()
            .gap_1()
            .child(heading("INVESTIGATION ARTIFACTS", cx));
        for group in ArtifactGroup::SHORTCUTS {
            shortcuts = shortcuts.child(self.render_artifact_shortcut(group, cx));
        }
        div()
            .w(px(282.))
            .flex_shrink_0()
            .h_full()
            .flex()
            .flex_col()
            .gap_3()
            .p_3()
            .border_r_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().sidebar)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(heading("EVIDENCE", cx))
                    .child(
                        Button::new("add-evidence")
                            .accessibility_label("Add evidence files")
                            .xsmall()
                            .ghost()
                            .icon(IconName::Plus)
                            .tooltip("Add evidence files")
                            .disabled(self.busy.is_some())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_path("evidence", window, cx)
                            })),
                    ),
            )
            .child(evidence)
            .child(heading("ARTIFACT BROWSER", cx))
            .child(tabs)
            .child(
                Input::new(&self.browser_query)
                    .id("artifact-filter")
                    .aria_label("Filter artifact browser")
                    .small()
                    .cleanable(true),
            )
            .child(mode)
            .child(div().flex_1().min_h_0().overflow_hidden().child(browser))
            .child(shortcuts)
            .into_any_element()
    }
    fn render_welcome(&self, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex_1()
            .p_8()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_2xl().child("No case open"))
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Create a case or continue an investigation."),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        Button::new("welcome-new-case")
                            .primary()
                            .label("New case")
                            .disabled(!self.can_switch())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.navigate(View::NewCase, cx);
                            })),
                    )
                    .child(
                        Button::new("welcome-open-case")
                            .label("Open case")
                            .disabled(!self.can_switch())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_path("open", window, cx)
                            })),
                    )
                    .child(
                        Button::new("welcome-recent-cases")
                            .label("Open recent case")
                            .disabled(!self.can_switch() || self.settings.recent_cases.is_empty())
                            .dropdown_caret(true)
                            .dropdown_menu({
                                let recent = self.settings.recent_cases.clone();
                                let weak = cx.entity().downgrade();
                                move |mut menu, _, _| {
                                    for path in &recent {
                                        menu = menu.item(Self::file_item(
                                            path.parent()
                                                .unwrap_or(path)
                                                .file_name()
                                                .unwrap_or_default()
                                                .to_string_lossy()
                                                .into_owned(),
                                            FileCommand::Recent(path.clone()),
                                            false,
                                            weak.clone(),
                                        ));
                                    }
                                    menu
                                }
                            }),
                    ),
            )
            .when(self.installation.is_none(), |s| {
                s.child(
                    Button::new("configure-engine")
                        .small()
                        .label("Configure Volatility")
                        .on_click(
                            cx.listener(|this, _, window, cx| this.open_settings(window, cx)),
                        ),
                )
            })
            .into_any_element()
    }
    fn render_new_case(&self, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex_1()
            .p_6()
            .child(
                div()
                    .max_w(px(720.))
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(div().text_2xl().child("New case"))
                    .child(heading("Name", cx))
                    .child(
                        Input::new(&self.case_name)
                            .id("case-name")
                            .aria_label("Case name"),
                    )
                    .child(heading("Directory", cx))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Input::new(&self.case_directory)
                                    .id("case-directory")
                                    .aria_label("Case directory")
                                    .flex_1(),
                            )
                            .child(Button::new("browse-case").label("Browse").on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.choose_path("directory", window, cx)
                                }),
                            )),
                    )
                    .child(
                        Button::new("create-case")
                            .primary()
                            .w(px(150.))
                            .label("Create case")
                            .disabled(!self.can_switch())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.create_case(window, cx)),
                            ),
                    ),
            )
            .into_any_element()
    }
    pub(super) fn open_analysis_dialog(
        &mut self,
        targets: Vec<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.busy.as_ref().is_some_and(|b| b.run_id.is_none()) || !self.save_note(cx) {
            return;
        }
        self.analysis_drafts = self
            .case
            .as_ref()
            .map(|case| {
                targets
                    .iter()
                    .filter_map(|id| {
                        case.document
                            .evidence
                            .iter()
                            .find(|e| &e.id == id)
                            .map(AnalysisDraft::new)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if self.analysis_drafts.is_empty() {
            self.error = Some("Add evidence before choosing analyses".into());
            cx.notify();
            return;
        }
        self.analysis_active = 0;
        self.show_advanced = false;
        self.analysis_error = None;
        self.analysis_group_filter = None;
        self.plugin = None;
        self.plugin_help.clear();
        self.plugin_query
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.arguments
            .update(cx, |s, cx| s.set_value("", window, cx));
        let workspace = cx.entity().downgrade();
        let panel = cx.new(|cx| AnalysisPanel {
            _subscription: cx.observe(&workspace.upgrade().unwrap(), |_, _, cx| cx.notify()),
            workspace: workspace.clone(),
        });
        let width = (window.viewport_size().width - px(64.)).min(px(1100.));
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .title("Choose analyses")
                .width(width)
                .overlay_closable(false)
                .child(panel.clone())
        });
        cx.notify();
    }
    fn render_plugins(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let Some(draft) = self.analysis_drafts.get(self.analysis_active) else {
            return div().into_any_element();
        };
        let total: usize = self.analysis_drafts.iter().map(|d| d.selected.len()).sum();
        let mut evidence = div().flex().gap_2().items_center().flex_wrap();
        for (i, draft) in self.analysis_drafts.iter().enumerate() {
            let name = self
                .case
                .as_ref()
                .and_then(|c| {
                    c.document
                        .evidence
                        .iter()
                        .find(|e| e.id == draft.evidence_id)
                })
                .map_or_else(|| "Evidence".into(), |e| e.name());
            evidence = evidence.child(
                Button::new(key("analysis-evidence", &draft.evidence_id))
                    .small()
                    .label(format!("{name} · {} selected", draft.selected.len()))
                    .selected(i == self.analysis_active)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_analysis_evidence(i, window, cx)
                    })),
            );
        }
        let mut os = div()
            .flex()
            .items_center()
            .gap_2()
            .child(heading("EVIDENCE OS", cx));
        for target in OperatingSystem::TARGETS {
            os = os.child(
                Button::new(key("os", target.label()))
                    .small()
                    .label(target.label())
                    .selected(target == draft.os)
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.set_os(target, window, cx)),
                    ),
            );
        }
        let height = (window.viewport_size().height - px(210.)).clamp(px(320.), px(590.));
        let mut page = div()
            .flex()
            .flex_col()
            .gap_3()
            .h(height)
            .min_h_0()
            .child(evidence)
            .child(os);
        let Some(engine) = &self.installation else {
            return page.child(div().text_sm().child("Configure Volatility to choose analyses. The evidence has already been added to the case."))
                .child(Button::new("analysis-settings").label("Configure Volatility").on_click(cx.listener(|this,_,window,cx| this.open_settings(window,cx))))
                .child(Button::new("analysis-later").label("Choose later").on_click(|_,window,cx| window.close_dialog(cx))).into_any_element();
        };
        let mut plugins = chooser_plugins(
            &engine.plugins,
            draft.os,
            self.show_advanced,
            self.plugin_query.read(cx).value().as_ref(),
        );
        if let Some(group) = self.analysis_group_filter {
            plugins.retain(|p| ArtifactGroup::for_plugin(&p.id) == group);
        }
        let visible_ids: Vec<_> = plugins.iter().map(|p| p.id.clone()).collect();
        let range_ids = Rc::new(visible_ids.clone());
        let all_visible_selected =
            !visible_ids.is_empty() && visible_ids.iter().all(|id| draft.selected.contains(id));
        let basic_count = plugins
            .iter()
            .filter(|p| basic_label(&p.id).is_some())
            .count();
        page = page.child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    Input::new(&self.plugin_query)
                        .id("plugin-search")
                        .aria_label("Search analyses")
                        .small()
                        .cleanable(true)
                        .flex_1(),
                )
                .child(
                    Checkbox::new("show-advanced")
                        .label("Show advanced analyses")
                        .checked(self.show_advanced)
                        .on_change(cx.listener(|this, value, _, cx| {
                            this.show_advanced = *value;
                            cx.notify();
                        })),
                ),
        );
        let selected = draft.selected.clone();
        let focused = self.plugin.clone();
        let header = div()
            .id("analysis-table-header")
            .flex()
            .items_center()
            .h(px(34.))
            .gap_2()
            .px_2()
            .bg(cx.theme().muted)
            .role(Role::Row)
            .child(
                div().w(px(24.)).child(
                    Checkbox::new("select-visible-analyses")
                        .accessibility_label("Select all visible analyses")
                        .checked(all_visible_selected)
                        .disabled(visible_ids.is_empty())
                        .on_change(cx.listener(move |this, value, _, cx| {
                            if let Some(draft) = this.analysis_drafts.get_mut(this.analysis_active)
                            {
                                for id in &visible_ids {
                                    if *value {
                                        draft.selected.insert(id.clone());
                                    } else {
                                        draft.selected.remove(id);
                                    }
                                }
                            }
                            cx.notify();
                        })),
                ),
            )
            .child(
                div()
                    .id("analysis-name-header")
                    .flex_1()
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Analysis"),
            )
            .child(
                div()
                    .id("analysis-plugin-header")
                    .flex_1()
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Plugin"),
            )
            .child(
                div()
                    .id("analysis-level-header")
                    .w(px(70.))
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Level"),
            )
            .child(
                div()
                    .id("analysis-options-header")
                    .w(px(58.))
                    .role(Role::ColumnHeader)
                    .text_xs()
                    .child("Options"),
            );
        let len = plugins.len();
        let list = uniform_list(
            "analysis-table-rows",
            len,
            cx.processor(move |_, range: Range<usize>, _, cx| {
                range
                    .map(|i| {
                        let plugin = &plugins[i];
                        let id = plugin.id.clone();
                        let check_id = id.clone();
                        let range_ids = range_ids.clone();
                        let options_id = id.clone();
                        let label = basic_label(&id)
                            .map(str::to_owned)
                            .unwrap_or_else(|| id.rsplit('.').next().unwrap_or(&id).to_string());
                        let basic = basic_label(&id).is_some();
                        let description = plugin.description.clone();
                        div()
                            .id(key("analysis-row", &id))
                            .role(Role::Row)
                            .w_full()
                            .h(px(38.))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_2()
                            .border_b_1()
                            .border_color(cx.theme().border)
                            .when(focused.as_ref() == Some(&id), |row| {
                                row.bg(cx.theme().accent)
                            })
                            .child(
                                div().w(px(24.)).child(
                                    Checkbox::new(key("select-analysis", &id))
                                        .accessibility_label(format!("Select {id}"))
                                        .checked(selected.contains(&id))
                                        .on_change(cx.listener(move |this, value, window, cx| {
                                            if let Some(draft) =
                                                this.analysis_drafts.get_mut(this.analysis_active)
                                            {
                                                draft.select(
                                                    &check_id,
                                                    *value,
                                                    window.modifiers().shift,
                                                    &range_ids,
                                                );
                                            }
                                            this.analysis_error = None;
                                            cx.notify();
                                        })),
                                ),
                            )
                            .child(
                                div()
                                    .id(key("analysis-label", &id))
                                    .flex_1()
                                    .min_w_0()
                                    .text_sm()
                                    .truncate()
                                    .child(label)
                                    .tooltip(move |window, cx| {
                                        Tooltip::new(description.clone()).build(window, cx)
                                    }),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .truncate()
                                    .child(id.clone()),
                            )
                            .child(
                                div()
                                    .w(px(70.))
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(if basic { "Basic" } else { "Advanced" }),
                            )
                            .child(
                                Button::new(key("analysis-options", &id))
                                    .xsmall()
                                    .ghost()
                                    .label("Options")
                                    .w(px(58.))
                                    .tooltip(format!("Options for {id}"))
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.focus_plugin(options_id.clone(), window, cx)
                                    })),
                            )
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .flex_1()
        .w_full()
        .min_h_0();
        let table = div()
            .id("analysis-table")
            .role(Role::Table)
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .border_1()
            .border_color(cx.theme().border)
            .child(header)
            .when(len == 0, |s| {
                s.child(div().p_4().text_sm().child(
                    "No matching analyses. Try showing advanced analyses or changing the search.",
                ))
            })
            .child(list);
        let mut body = div().flex().flex_1().min_h_0().gap_3().child(table);
        if let Some(id) = &self.plugin {
            body=body.child(div().flex().flex_col().gap_3().w(px(255.)).flex_shrink_0()
                .child(heading("PLUGIN OPTIONS",cx))
                .child(div().text_sm().child(id.clone()))
                .child(Input::new(&self.arguments).id("plugin-arguments").aria_label("Plugin arguments").small())
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Options are saved separately for each analysis. Select its checkbox to include it in the queue."))
                .child(Button::new("load-options").small().label("Load options").disabled(self.busy.is_some()).on_click(cx.listener(|this,_,_,cx| this.plugin_help(cx))))
                .child(div().id("plugin-help").flex_1().min_h_0().overflow_y_scroll().text_xs().font_family("Consolas").child(self.plugin_help.clone())));
        }
        page.child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{basic_count} basic · {} advanced · Shift-click checkboxes to select a range",
                    len - basic_count
                )),
        )
        .child(body)
        .when_some(self.analysis_error.clone(), |s, error| {
            s.child(div().text_sm().text_color(cx.theme().danger).child(error))
        })
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(div().flex_1().text_sm().child(format!(
                    "{total} analyses selected across {} evidence file(s)",
                    self.analysis_drafts.len()
                )))
                .child(
                    Button::new("cancel-analysis-selection")
                        .small()
                        .label("Choose later")
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                )
                .child(
                    Button::new("confirm-analyses")
                        .small()
                        .primary()
                        .label(format!("Queue {total} analyses"))
                        .disabled(
                            total == 0 || self.busy.as_ref().is_some_and(|b| b.run_id.is_none()),
                        )
                        .on_click(
                            cx.listener(|this, _, window, cx| this.queue_analyses(window, cx)),
                        ),
                ),
        )
        .into_any_element()
    }
    fn render_analyses(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("analyses")
            .flex_1()
            .overflow_y_scrollbar()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().text_xl().child("Analysis history"));
        let Some(case) = &self.case else {
            return page.into_any_element();
        };
        if self.queue_paused {
            page = page.child(
                Button::new("resume-queue")
                    .label("Retry save and resume queue")
                    .on_click(cx.listener(|this, _, _, cx| {
                        match this.case.as_mut().unwrap().save() {
                            Ok(()) => this.queue_paused = false,
                            Err(e) => this.error = Some(e),
                        }
                        cx.notify();
                    })),
            );
        }
        for run in case.document.runs.iter().rev() {
            let id = run.id.clone();
            let cancel = id.clone();
            let rerun = id.clone();
            let mut actions = div().flex().flex_col().gap_1().child(
                Button::new(key("inspect", &id))
                    .small()
                    .label("Inspect")
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.select_run(id.clone(), window, cx)
                    })),
            );
            if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                actions = actions.child(
                    Button::new(key("cancel", &cancel))
                        .small()
                        .label("Cancel")
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.cancel_run(cancel.clone(), cx)),
                        ),
                );
            } else {
                actions = actions.child(
                    Button::new(key("rerun", &rerun))
                        .small()
                        .label("Rerun setup")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(run) = this
                                .case
                                .as_ref()
                                .and_then(|c| c.document.runs.iter().find(|r| r.id == rerun))
                                .cloned()
                            {
                                let target = run.evidence_id.clone();
                                this.open_analysis_dialog(vec![target], window, cx);
                                if let Some(draft) = this.analysis_drafts.first_mut() {
                                    draft.selected.insert(run.plugin.clone());
                                    draft.arguments.insert(
                                        run.plugin.clone(),
                                        format_arguments(&run.arguments),
                                    );
                                }
                                this.show_advanced = basic_label(&run.plugin).is_none();
                                this.focus_plugin(run.plugin, window, cx);
                            }
                        })),
                );
            }
            if matches!(run.status, RunStatus::Failed | RunStatus::Interrupted) {
                let retry = run.id.clone();
                actions = actions.child(
                    Button::new(key("retry-analysis", &retry))
                        .small()
                        .label("Retry")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.retry_run(&retry, window, cx)
                        })),
                );
            }
            let summary = if matches!(run.status, RunStatus::Running | RunStatus::Queued) {
                run.status.label().to_string()
            } else {
                format!("{} · {} records", run.status.label(), run.row_count)
            };
            page = page.child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .p_3()
                    .border_1()
                    .border_color(cx.theme().border)
                    .rounded_md()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .truncate()
                                    .when(run.status == RunStatus::Cancelled, |text| {
                                        text.text_color(cx.theme().muted_foreground)
                                    })
                                    .child(run.plugin.clone()),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(summary)
                                    .child(run.created_at.clone()),
                            )
                            .when(run.status == RunStatus::Failed, |text| {
                                text.child(
                                    div()
                                        .text_xs()
                                        .child(run.message.chars().take(500).collect::<String>()),
                                )
                            }),
                    )
                    .child(actions),
            );
        }
        page.into_any_element()
    }
    fn render_bookmarks(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("bookmarks-page")
            .flex_1()
            .overflow_y_scrollbar()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().text_xl().child("Bookmarks and notes"));
        if let Some(case) = &self.case {
            for (i, a) in case.document.annotations.iter().enumerate() {
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
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .text_sm()
                                        .truncate()
                                        .child(format!("{title} · row {}", row + 1)),
                                )
                                .when(!a.note.is_empty(), |text| {
                                    text.child(
                                        div()
                                            .text_xs()
                                            .text_color(cx.theme().muted_foreground)
                                            .truncate()
                                            .child(a.note.clone()),
                                    )
                                }),
                        )
                        .child(
                            Button::new(("open-note", i))
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
    fn render_case_info(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut page = div()
            .id("case-info-page")
            .flex_1()
            .overflow_y_scrollbar()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_xl().child("Case information"));
        if let Some(case) = &self.case {
            page = page
                .child(div().text_sm().child(case.document.name.clone()))
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(case.directory.display().to_string()),
                )
                .child(
                    Button::new("export-report")
                        .small()
                        .w(px(160.))
                        .label("Export case report")
                        .on_click(cx.listener(|this, _, window, cx| this.export(true, window, cx))),
                );
            for e in &case.document.evidence {
                let id = e.id.clone();
                page = page.child(
                    section(e.name(), cx)
                        .child(div().text_xs().child(e.path.display().to_string()))
                        .child(div().text_xs().child(format!(
                            "{} · OS: {}",
                            format_bytes(e.size),
                            e.operating_system.label()
                        )))
                        .child(heading("SHA-256", cx))
                        .child(
                            div()
                                .text_xs()
                                .font_family("Consolas")
                                .child(e.sha256.clone()),
                        )
                        .child(
                            Button::new(key("verify", &id))
                                .small()
                                .w(px(140.))
                                .label("Verify integrity")
                                .disabled(self.busy.is_some())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.selected_evidence = Some(id.clone());
                                    this.verify(cx);
                                })),
                        ),
                )
            }
        }
        page.into_any_element()
    }
}

struct AnalysisPanel {
    workspace: WeakEntity<Workspace>,
    _subscription: Subscription,
}
impl Render for AnalysisPanel {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.workspace
            .update(cx, |workspace, cx| workspace.render_plugins(window, cx))
            .unwrap_or_else(|_| div().into_any_element())
    }
}

struct SettingsPanel {
    workspace: WeakEntity<Workspace>,
    _subscription: Subscription,
}
impl Render for SettingsPanel {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.workspace
            .update(cx, |w, cx| w.render_settings_content(cx))
            .unwrap_or_else(|_| div().into_any_element())
    }
}

impl Render for Workspace {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let weak = cx.entity().downgrade();
        let file_weak = weak.clone();
        let case_open = self.case.is_some();
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
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("volgui"),
                )
                .child(div().h_4().w_px().bg(cx.theme().border))
                .child(
                    div()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .child(
                            Button::new("file-menu")
                                .ghost()
                                .xsmall()
                                .label("File")
                                .dropdown_caret(true)
                                .dropdown_menu(move |menu, window, cx| {
                                    Self::file_menu(file_weak.clone(), menu, window, cx)
                                }),
                        ),
                ),
        );
        let mut toolbar = div()
            .flex()
            .flex_shrink_0()
            .items_center()
            .gap_1()
            .px_3()
            .py_2()
            .border_b_1()
            .border_color(cx.theme().border);
        toolbar = toolbar.child(
            Button::new("navigate-back")
                .accessibility_label("Back")
                .small()
                .ghost()
                .icon(IconName::ArrowLeft)
                .tooltip("Back")
                .disabled(self.back_stack.is_empty())
                .on_click(cx.listener(|this, _, window, cx| this.go_back(window, cx))),
        );
        for (id, label, view) in [
            ("nav-workspace", "Workspace", View::Workspace),
            ("nav-bookmarks", "Bookmarks", View::Bookmarks),
            ("nav-case", "Case info", View::CaseInfo),
        ] {
            toolbar = toolbar.child(
                Button::new(id)
                    .small()
                    .ghost()
                    .label(label)
                    .disabled(!case_open)
                    .selected(self.view == view)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.navigate(view, cx);
                    })),
            );
        }
        toolbar = toolbar.child(div().ml_auto()).child(
            Button::new("new-analysis")
                .small()
                .primary()
                .icon(IconName::Plus)
                .label("New analysis")
                .disabled(!case_open)
                .on_click(cx.listener(|this, _, window, cx| {
                    this.open_analysis_dialog(
                        this.selected_evidence.iter().cloned().collect(),
                        window,
                        cx,
                    );
                })),
        );
        let content = match self.view {
            View::Welcome => self.render_welcome(cx),
            View::NewCase => self.render_new_case(cx),
            View::Workspace => self.render_workspace(cx),
            View::Analyses => self.render_analyses(cx),
            View::Bookmarks => self.render_bookmarks(cx),
            View::CaseInfo => self.render_case_info(cx),
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
        let running = self.busy.as_ref().is_some_and(|b| b.run_id.is_some());
        let label = if running || queued > 0 {
            format!("{} running · {queued} queued", usize::from(running))
        } else {
            format!(
                "{} analyses · Ready",
                self.case
                    .as_ref()
                    .map_or(0, |c| c.document.queue_runs().count())
            )
        };
        let progress = if self.batch_total == 0 {
            0.
        } else {
            self.batch_finished as f32 / self.batch_total as f32 * 100.
        };
        let queue_panel = self.popup_panel(popups::PanelKind::Queue, cx);
        let status = div()
            .flex()
            .flex_shrink_0()
            .h(px(38.))
            .items_center()
            .px_3()
            .gap_3()
            .border_t_1()
            .border_color(cx.theme().border)
            .child(
                Button::new("toggle-sidebar")
                    .xsmall()
                    .ghost()
                    .icon(IconName::PanelLeft)
                    .accessibility_label("Toggle evidence sidebar")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.sidebar_visible = !this.sidebar_visible;
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_xs()
                    .truncate()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.message.clone()),
            )
            .when(
                self.busy.as_ref().is_some_and(|b| b.run_id.is_none()),
                |s| {
                    s.child(
                        Button::new("cancel-work")
                            .xsmall()
                            .ghost()
                            .label("Cancel")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(b) = &this.busy {
                                    b.cancel.store(true, Ordering::Relaxed);
                                }
                                cx.notify();
                            })),
                    )
                },
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        ProgressCircle::new("queue-progress")
                            .xsmall()
                            .value(progress)
                            .loading(running && self.batch_finished == 0)
                            .accessibility_label("Finished analyses in current batch"),
                    )
                    .child(
                        Popover::new("queue-popover")
                            .anchor(Anchor::BottomRight)
                            .open(self.queue_open)
                            .on_open_change(cx.listener(|this, open, _, cx| {
                                this.queue_open = *open;
                                cx.notify();
                            }))
                            .trigger(
                                Button::new("queue-indicator")
                                    .xsmall()
                                    .ghost()
                                    .label(label)
                                    .tooltip(
                                        self.busy
                                            .as_ref()
                                            .map(|b| b.label.clone())
                                            .unwrap_or_else(|| "Recent analyses and queue".into()),
                                    )
                                    .dropdown_caret(true),
                            )
                            .content(move |_, _, _| queue_panel.clone()),
                    ),
            );
        div()
            .id("workspace-root")
            .track_focus(&self.workspace_focus)
            .on_action(
                cx.listener(|_, _: &gpui_kit::base::input::Copy, window, cx| {
                    let text = gpui_kit::base::TextSelection::selected_text(window, cx);
                    if text.is_empty() {
                        cx.propagate();
                    } else {
                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                    }
                }),
            )
            .on_drag_move::<artifacts_view::ColumnResize>(
                cx.listener(|this, event, _, cx| this.resize_column(event, cx)),
            )
            .flex()
            .flex_col()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(title)
            .child(toolbar)
            .when_some(self.error.clone(), |s, e| {
                s.child(
                    div()
                        .flex()
                        .items_start()
                        .px_4()
                        .py_2()
                        .gap_3()
                        .bg(rgb(0x321d25))
                        .child(
                            div()
                                .id("error-message")
                                .flex_1()
                                .max_h(px(70.))
                                .overflow_y_scroll()
                                .text_xs()
                                .child(e),
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
