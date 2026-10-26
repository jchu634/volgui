// Renders processes beneath their parents. PPID remains in record details.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_processes(&self, cx: &mut Context<Self>) -> AnyElement {
        self.render_artifact_tree(ArtifactGroup::Processes, cx)
    }

    pub(in crate::ui) fn render_process_node(
        &self,
        i: usize,
        depth: usize,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let node = &self.result_tree.nodes[i];
        if matches!(node.kind, volgui::result_tree::TreeNodeKind::File) {
            let id = node.record_id;
            return self
                .artifact_tree_row(i, depth, cx)
                .child(Icon::new(IconName::File).size_4().flex_shrink_0())
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .child(node.label.clone()),
                )
                .when_some(
                    id.and_then(|id| self.file_recovery_states.get(&id)),
                    |row, state| {
                        row.child(
                            div()
                                .flex_shrink_0()
                                .text_color(cx.theme().muted_foreground)
                                .child(state.label()),
                        )
                    },
                )
                .when_some(id, |row, id| {
                    row.child(
                        app_button(("show-handle-in-files", i))
                            .xsmall()
                            .label("Show in Files")
                            .disabled(!self.row_cache.contains_key(&id))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                cx.stop_propagation();
                                this.show_file_in_files(id, window, cx);
                            })),
                    )
                })
                .into_any_element();
        }
        let record = node.record_id.and_then(|id| self.row_cache.get(&id));
        let summary = record
            .map(|record| {
                self.result_columns()
                    .iter()
                    .filter(|c| !matches!(c.label.as_str(), "Process" | "PID"))
                    .filter_map(|c| {
                        let text = c.text(&record.record);
                        (!text.is_empty() && text != "N/A").then(|| format!("{}: {text}", c.label))
                    })
                    .collect::<Vec<_>>()
                    .join(" · ")
            })
            .unwrap_or_default();
        self.artifact_tree_row(i, depth, cx)
            .when(depth > 0, |row| row.child("└"))
            .child(Icon::new(IconName::Cpu).size_4().flex_shrink_0())
            .child(div().flex_shrink_0().child(node.label.clone()))
            .when_some(node.pid.as_ref(), |row, pid| {
                row.child(
                    div()
                        .flex_shrink_0()
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("PID {pid}")),
                )
            })
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .text_color(cx.theme().muted_foreground)
                    .child(summary),
            )
            .into_any_element()
    }
}
