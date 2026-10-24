// Builds title bar menus and the settings dialog.
use super::*;
use gpui_kit::component::dialog::DialogButtonProps;

impl Workspace {
    // The modal backdrop covers the title bar's native hit-test regions.
    // Paint only the window controls above it, leaving application controls modal.
    pub(in crate::ui) fn render_modal_window_controls(
        &self,
        window: &Window,
        cx: &App,
    ) -> impl IntoElement {
        // Match gpui-kit 0.8 TitleBar dimensions.
        const TITLE_BAR_HEIGHT: Pixels = px(34.);

        deferred(
            div()
                .absolute()
                .top_0()
                .right_0()
                .h(TITLE_BAR_HEIGHT)
                .flex()
                .children(
                    [
                        (
                            "modal-minimize",
                            IconName::WindowMinimize,
                            WindowControlArea::Min,
                        ),
                        (
                            "modal-maximize",
                            if window.is_maximized() {
                                IconName::WindowRestore
                            } else {
                                IconName::WindowMaximize
                            },
                            WindowControlArea::Max,
                        ),
                        (
                            "modal-close",
                            IconName::WindowClose,
                            WindowControlArea::Close,
                        ),
                    ]
                    .into_iter()
                    .map(|(id, icon, area)| {
                        div()
                            .id(id)
                            .w(TITLE_BAR_HEIGHT)
                            .h_full()
                            .flex()
                            .items_center()
                            .justify_center()
                            .bg(cx.theme().title_bar)
                            .hover(|style| {
                                if id == "modal-close" {
                                    style
                                        .bg(cx.theme().danger)
                                        .text_color(cx.theme().danger_foreground)
                                } else {
                                    style.bg(cx.theme().secondary_hover)
                                }
                            })
                            .window_control_area(area)
                            .child(Icon::new(icon).small())
                    }),
                ),
        )
        .with_priority(100)
    }
    pub(in crate::ui) fn file_item(
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
    pub(in crate::ui) fn file_menu(
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
    pub(in crate::ui) fn view_menu(
        weak: WeakEntity<Self>,
        mut menu: PopupMenu,
        cx: &mut Context<PopupMenu>,
    ) -> PopupMenu {
        let Some(workspace) = weak.upgrade() else {
            return menu;
        };
        let workspace = workspace.read(cx);
        let disabled = workspace.case.is_none();
        let current = workspace.view;
        for (label, view) in [
            ("Workspace", View::Workspace),
            ("Case info", View::CaseInfo),
        ] {
            let weak = weak.clone();
            menu = menu.item(
                PopupMenuItem::new(label)
                    .disabled(disabled)
                    .checked(current == view)
                    .on_click(move |_, _, cx| {
                        let _ = weak.update(cx, |this, cx| this.navigate(view, cx));
                    }),
            );
        }
        menu
    }
    pub(in crate::ui) fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
    pub(in crate::ui) fn render_settings_content(&self, cx: &mut Context<Self>) -> AnyElement {
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
}
#[derive(Clone)]
pub(super) enum FileCommand {
    New,
    Open,
    Recent(PathBuf),
    Evidence,
    Settings,
    Close,
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
