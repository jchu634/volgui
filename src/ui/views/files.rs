// Renders file records under shared directory branches.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_files(&self, cx: &mut Context<Self>) -> AnyElement {
        self.render_artifact_tree(ArtifactGroup::Files, cx)
    }

    pub(in crate::ui) fn render_file_node(
        &self,
        i: usize,
        depth: usize,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let node = &self.result_tree.nodes[i];
        self.artifact_tree_row(i, depth, cx)
            .child(self.artifact_tree_toggle(i, cx))
            .child(
                Icon::new(if node.record_id.is_none() {
                    IconName::Folder
                } else {
                    IconName::File
                })
                .size_4()
                .flex_shrink_0(),
            )
            .child(
                div()
                    .min_w_0()
                    .flex_1()
                    .truncate()
                    .child(node.label.clone()),
            )
            .when_some(
                node.record_id
                    .and_then(|id| self.file_recovery_states.get(&id)),
                |row, state| {
                    row.child(
                        div()
                            .flex_shrink_0()
                            .text_color(cx.theme().muted_foreground)
                            .child(state.label()),
                    )
                },
            )
            .into_any_element()
    }
}
