// Renders evidence selection, main view buttons, and artifact shortcuts.
use super::*;

impl Workspace {
    pub(in crate::ui) fn group_icon(group: ArtifactGroup) -> IconName {
        match group {
            ArtifactGroup::Processes => IconName::Cpu,
            ArtifactGroup::Network => IconName::Network,
            ArtifactGroup::Files => IconName::Folder,
            ArtifactGroup::Web => IconName::Network,
            ArtifactGroup::Strings => IconName::Search,
            ArtifactGroup::Registry => IconName::Database,
            ArtifactGroup::Memory => IconName::Shield,
            ArtifactGroup::System => IconName::Info,
            ArtifactGroup::Commands => IconName::Terminal,
            ArtifactGroup::Modules => IconName::Layers,
            ArtifactGroup::Sessions => IconName::Users,
            ArtifactGroup::Other => IconName::Archive,
        }
    }
    pub(in crate::ui) fn render_sidebar(&self, cx: &mut Context<Self>) -> AnyElement {
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
        let mut tabs = div().flex().flex_col().gap_1().flex_shrink_0();
        let mut browser_registry = div()
            .flex()
            .flex_col()
            .gap_1()
            .flex_shrink_0()
            .child(heading("BROWSER AND REGISTRY", cx));
        for group in ArtifactGroup::BROWSER {
            let label = if group == ArtifactGroup::Files {
                "Files"
            } else {
                group.label()
            };
            let button = Button::new(key("browser", label))
                .small()
                .ghost()
                .accessibility_label(label)
                .w_full()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .w_full()
                        .child(Icon::new(Self::group_icon(group)).size_4())
                        .child(label),
                )
                .selected(self.view == View::Workspace && self.browser_group == group)
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.choose_group(group, window, cx);
                }));
            if matches!(group, ArtifactGroup::Web | ArtifactGroup::Registry) {
                browser_registry = browser_registry.child(button);
            } else {
                tabs = tabs.child(button);
            }
        }
        tabs = tabs.child(
            Button::new("nav-bookmarks")
                .small()
                .ghost()
                .w_full()
                .accessibility_label("Bookmarks")
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .w_full()
                        .child(Icon::new(IconName::Bookmark).size_4())
                        .child("Bookmarks"),
                )
                .selected(self.view == View::Bookmarks)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.navigate(View::Bookmarks, cx);
                })),
        );
        let mut shortcuts = div()
            .flex_shrink_0()
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
                            .disabled(self.is_working())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_path("evidence", window, cx)
                            })),
                    ),
            )
            .child(evidence)
            .child(tabs)
            .child(div().flex_1().min_h_0())
            .child(browser_registry)
            .child(shortcuts)
            .into_any_element()
    }
}
