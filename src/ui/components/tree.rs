// Shares virtual scrolling and branch interactions for artifact trees.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_artifact_tree(
        &self,
        group: ArtifactGroup,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let list = uniform_list(
            "artifact-tree-virtual",
            self.result_tree.visible.len(),
            cx.processor(move |this, range: Range<usize>, _, cx| {
                let visible = this.result_tree.visible.get(range).unwrap_or(&[]).to_vec();
                this.request_record_ids(
                    visible
                        .iter()
                        .filter_map(|(i, _)| this.result_tree.nodes[*i].record_id)
                        .collect(),
                );
                visible
                    .into_iter()
                    .map(|(i, depth)| match group {
                        ArtifactGroup::Processes => this.render_process_node(i, depth, cx),
                        ArtifactGroup::Registry => this.render_registry_node(i, depth, cx),
                        _ => this.render_file_node(i, depth, cx),
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(&self.result_scroll)
        .size_full();
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(self.render_results_toolbar(cx))
            .when(group == ArtifactGroup::Registry, |view| {
                view.child(self.render_investigation_tools(cx))
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_1()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(heading(
                        if group == ArtifactGroup::Processes {
                            "Process hierarchy"
                        } else if group == ArtifactGroup::Registry {
                            "Registry hierarchy"
                        } else {
                            "Directory hierarchy"
                        },
                        cx,
                    ))
                    .child(div().flex_1())
                    .when(group == ArtifactGroup::Processes, |header| {
                        header.child(
                            Checkbox::new("show-process-file-handles")
                                .label("Show file handles")
                                .checked(self.show_file_handles)
                                .on_click(cx.listener(|this, checked, _, cx| {
                                    this.show_file_handles = *checked;
                                    this.selection_epoch += 1;
                                    this.tree_cursor = None;
                                    this.result_tree = ResultTree::default();
                                    this.start_query(cx);
                                })),
                        )
                    })
                    .child(
                        Button::new("tree-expand-all")
                            .xsmall()
                            .ghost()
                            .label("Expand all")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.result_tree.expand_all(true);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("tree-collapse-all")
                            .xsmall()
                            .ghost()
                            .label("Collapse all")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.result_tree.expand_all(false);
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .id("artifact-tree")
                    .role(Role::Tree)
                    .aria_label(if group == ArtifactGroup::Processes {
                        "Process tree"
                    } else if group == ArtifactGroup::Registry {
                        "Registry tree"
                    } else {
                        "File tree"
                    })
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(list)
                    .when(self.index.ids.is_empty(), |body| {
                        body.child(
                            div()
                                .absolute()
                                .top(px(24.))
                                .left_0()
                                .right_0()
                                .px_4()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(self.results_empty_message(cx)),
                        )
                    })
                    .child(Scrollbar::vertical(&self.result_scroll).mode(ScrollbarMode::Always)),
            )
            .into_any_element()
    }

    fn render_registry_node(&self, i: usize, depth: usize, cx: &mut Context<Self>) -> AnyElement {
        let node = &self.result_tree.nodes[i];
        let value = matches!(node.kind, volgui::result_tree::TreeNodeKind::RegistryValue);
        self.artifact_tree_row(i, depth, cx)
            .child(
                Icon::new(if value {
                    IconName::File
                } else {
                    IconName::Folder
                })
                .size_4()
                .flex_shrink_0(),
            )
            .child(div().min_w_0().truncate().child(node.label.clone()))
            .into_any_element()
    }

    pub(in crate::ui) fn artifact_tree_row(
        &self,
        i: usize,
        depth: usize,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let node = &self.result_tree.nodes[i];
        let id = node.record_id;
        let branch = self.result_tree.has_children(i);
        let expanded = self.result_tree.expanded(i);
        let selected = self.tree_cursor.map_or_else(
            || id.is_some_and(|id| self.selected.as_ref().is_some_and(|r| r.id == id)),
            |cursor| cursor == i,
        );
        div()
            .id(("artifact-tree-row", i))
            .role(Role::TreeItem)
            .aria_label(node.label.clone())
            .aria_level(depth + 1)
            .aria_selected(selected)
            .when(branch, |row| row.aria_expanded(expanded))
            .flex()
            .items_center()
            .gap_2()
            .h(px(32.))
            .w_full()
            .min_w_0()
            .overflow_hidden()
            .pl(px(8. + depth as f32 * 18.))
            .pr(px(20.))
            .text_xs()
            .cursor_pointer()
            .bg(if selected {
                cx.theme().accent
            } else {
                cx.theme().background
            })
            .hover(|s| s.bg(cx.theme().muted))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| window.focus(&this.workspace_focus, cx)),
            )
            .on_click(cx.listener(move |this, _, _, cx| {
                this.tree_cursor = Some(i);
                if let Some(id) = id {
                    this.load_record(id, cx);
                } else {
                    this.result_tree.toggle(i);
                    cx.notify();
                }
            }))
            .child(if branch {
                Button::new(("tree-toggle", i))
                    .xsmall()
                    .ghost()
                    .icon(if expanded {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    })
                    .tooltip(if expanded {
                        "Collapse branch"
                    } else {
                        "Expand branch"
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.tree_cursor = Some(i);
                        this.result_tree.toggle(i);
                        cx.notify();
                    }))
                    .into_any_element()
            } else {
                div().w(px(24.)).flex_shrink_0().into_any_element()
            })
    }

    pub(in crate::ui) fn tree_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let visible = &self.result_tree.visible;
        if visible.is_empty() {
            return;
        }
        let current = self.tree_cursor.or_else(|| {
            self.selected.as_ref().and_then(|record| {
                visible
                    .iter()
                    .find(|(i, _)| self.result_tree.nodes[*i].record_id == Some(record.id))
                    .map(|(i, _)| *i)
            })
        });
        let position = visible.iter().position(|(i, _)| Some(*i) == current);
        let pos = position.unwrap_or(0);
        let (i, depth) = visible[pos];
        let target = match event.keystroke.key.as_str() {
            "up" => {
                if position.is_some() {
                    pos.saturating_sub(1)
                } else {
                    0
                }
            }
            "down" => {
                if position.is_some() {
                    (pos + 1).min(visible.len() - 1)
                } else {
                    0
                }
            }
            "home" => 0,
            "end" => visible.len() - 1,
            "left" => {
                if self.result_tree.has_children(i) && self.result_tree.expanded(i) {
                    self.result_tree.toggle(i);
                    pos
                } else {
                    visible[..pos]
                        .iter()
                        .rposition(|(_, ancestor_depth)| *ancestor_depth < depth)
                        .unwrap_or(pos)
                }
            }
            "right" => {
                if self.result_tree.has_children(i) && !self.result_tree.expanded(i) {
                    self.result_tree.toggle(i);
                    pos
                } else if visible
                    .get(pos + 1)
                    .is_some_and(|(_, next_depth)| *next_depth > depth)
                {
                    pos + 1
                } else {
                    pos
                }
            }
            "enter" | "space" => {
                if self.result_tree.nodes[i].record_id.is_none() {
                    self.result_tree.toggle(i);
                }
                pos
            }
            _ => return,
        };
        let node = self.result_tree.visible[target].0;
        self.tree_cursor = Some(node);
        self.result_scroll
            .scroll_to_item(target, ScrollStrategy::Nearest);
        if let Some(id) = self.result_tree.nodes[node].record_id {
            self.load_record(id, cx);
        }
        cx.stop_propagation();
        cx.notify();
    }
}
