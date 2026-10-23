use gpui_kit::component::{
    ActiveTheme, Collapsible, IconName, Selectable, Sizable, TitleBar, WindowExt,
    button::{Button, ButtonVariants},
    menu::{DropdownMenu, PopupMenuItem},
    separator::Separator,
    sidebar::*,
};
use gpui_kit::*;

//Placeholder Action
actions!(volgui, [SelectOption]);

fn open_settings(window: &mut Window, cx: &mut App) {
    window.open_dialog(cx, |dialog, _, _| {
        dialog
            .title("Settings")
            .child("Placeholder: Settings will go here.")
    });
}

struct AppTitleBar;
// struct AppSettings{
//     theme: String,
//     recent_projects:
//     vol_path: String,
// }

impl Render for AppTitleBar {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        TitleBar::new().child(
            div()
                .flex()
                .flex_1()
                .items_center()
                .justify_start()
                .gap_3()
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("VolGUI"),
                )
                .child(Separator::vertical().h_4())
                .child(
                    div().child(
                        Button::new("file-menu")
                            .ghost()
                            .xsmall()
                            .label("File")
                            .dropdown_caret(true)
                            .dropdown_menu(|menu, window, cx| {
                                menu.menu("New Project", Box::new(SelectOption))
                                    .menu("Open Project", Box::new(SelectOption))
                                    .submenu("Open Recent Project", window, cx, |menu, _, _| {
                                        menu.menu("Example Project", Box::new(SelectOption))
                                            .menu("Another Project", Box::new(SelectOption))
                                    })
                                    .separator()
                                    .menu("Add memory dump", Box::new(SelectOption))
                                    .separator()
                                    .item(PopupMenuItem::new("Settings").on_click(
                                        |_, window, cx| {
                                            open_settings(window, cx);
                                        },
                                    ))
                                    .menu("Exit", Box::new(SelectOption))
                            }),
                    ),
                )
                .child(
                    Button::new("help-menu")
                        .ghost()
                        .xsmall()
                        .label("Help")
                        .dropdown_caret(true)
                        .dropdown_menu(|menu, _, _| menu.menu("About", Box::new(SelectOption))),
                )
                .child(
                    div()
                        .ml_auto()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .child(
                            Button::new("settings")
                                .small()
                                .ghost()
                                .icon(IconName::Settings)
                                .on_click(|_, window, cx| {
                                    open_settings(window, cx);
                                }),
                        ),
                ), // .child(Button::new("help").ghost().icon(IconName::HelpCircle)),
        )
    }
}

const ARTIFACT_GROUPS: &[(&str, &[&str])] = &[
    ("Artifacts", &["Registry", "System Information"]),
    ("Raw Artifacts", &["Clipboard", "Files and Documents"]),
];

struct Application {
    title_bar: Entity<AppTitleBar>,
    tree_view: bool,
    sidebar_visible: bool,
    selected_artifact: Option<&'static str>,
}

impl Application {
    fn artifact_item(&self, name: &'static str, cx: &mut Context<Self>) -> SidebarMenuItem {
        SidebarMenuItem::new(name)
            .active(self.selected_artifact == Some(name))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected_artifact = Some(name);
                cx.notify();
            }))
    }
}

impl Render for Application {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dumps: &[(&str, &[&str])] = &[("Example Project", &["workstation.raw", "server.raw"])];
        let mut menu = SidebarMenu::new();
        for &(project, files) in dumps {
            if self.tree_view {
                menu = menu.child(
                    SidebarMenuItem::new(project)
                        .default_open(true)
                        .click_to_toggle(true)
                        .children(files.iter().map(|&name| self.artifact_item(name, cx))),
                );
            } else {
                menu = menu.children(files.iter().map(|&name| self.artifact_item(name, cx)));
            }
        }
        let mut artifacts = div().flex().flex_col().flex_shrink_0();
        for &(group, items) in ARTIFACT_GROUPS {
            artifacts = artifacts.child(
                SidebarGroup::new(group)
                    .child(
                        SidebarMenu::new()
                            .children(items.iter().map(|&name| self.artifact_item(name, cx))),
                    )
                    .collapsed(!self.sidebar_visible)
                    .render(format!("persistent-{group}"), window, cx),
            );
        }

        let mut body = div().flex().flex_1().min_h_0().w_full();
        body = body.child(
            Sidebar::new("evidence-sidebar")
                .collapsed(!self.sidebar_visible)
                .collapsible(true)
                .header(
                    SidebarHeader::new()
                        .child(
                            div()
                                .text_sm()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child("Evidence"),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_1()
                                .child(
                                    Button::new("sidebar-tree")
                                        .ghost()
                                        .xsmall()
                                        .label("Tree")
                                        .selected(self.tree_view)
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.tree_view = true;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("sidebar-list")
                                        .ghost()
                                        .xsmall()
                                        .label("List")
                                        .selected(!self.tree_view)
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.tree_view = false;
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
                .child(SidebarGroup::new("Memory dump").child(menu))
                .footer(SidebarFooter::new().child(artifacts)),
        );

        body = body.child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .p_4()
                .gap_2()
                .child(
                    div()
                        .text_lg()
                        .child(self.selected_artifact.unwrap_or("Evidence workspace")),
                )
                .child(div().text_sm().child(if self.selected_artifact.is_some() {
                    "Artifact results will appear here."
                } else {
                    "Select an artifact from the sidebar to get started."
                })),
        );

        div()
            .flex()
            .flex_col()
            .size_full()
            .child(self.title_bar.clone())
            .child(body)
            .child(
                div()
                    .flex()
                    .items_center()
                    .flex_shrink_0()
                    .h_8()
                    .px_3()
                    .gap_3()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .text_xs()
                    .child(
                        SidebarToggleButton::new()
                            .collapsed(!self.sidebar_visible)
                            .accessibility_label("Toggle evidence sidebar")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.sidebar_visible = !this.sidebar_visible;
                                cx.notify();
                            })),
                    )
                    .child(Separator::vertical().h_4())
                    .child("Ready")
                    .child(
                        div().ml_auto().child(
                            Button::new("analysis-status")
                                .ghost()
                                .xsmall()
                                .label("No analyses running")
                                .dropdown_caret(true)
                                .dropdown_menu_with_anchor(Anchor::BottomRight, {
                                    let selected = self.selected_artifact;
                                    move |menu, _, _| {
                                        menu.label("Analysis status")
                                            .label("No analyses running")
                                            .separator()
                                            .label("Current selection")
                                            .label(selected.unwrap_or("Nothing selected"))
                                    }
                                }),
                        ),
                    )
                    .child(
                        Button::new("toolbar-settings")
                            .ghost()
                            .xsmall()
                            .icon(IconName::Settings)
                            .on_click(|_, window, cx| open_settings(window, cx)),
                    ),
            )
    }
}

fn main() {
    application().with_assets(assets::Assets).run(|cx| {
        init(cx);

        open_window(TitleBar::window_options(), cx, |_, cx| {
            let title_bar = cx.new(|_| AppTitleBar);

            cx.new(|_| Application {
                title_bar,
                tree_view: true,
                sidebar_visible: true,
                selected_artifact: None,
            })
        })
        .expect("Failed to open window");
    });
}
