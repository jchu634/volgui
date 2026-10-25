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
            .child(
                Icon::new(if node.record_id.is_none() {
                    IconName::Folder
                } else {
                    IconName::File
                })
                .size_4()
                .flex_shrink_0(),
            )
            .child(div().min_w_0().truncate().child(node.label.clone()))
            .into_any_element()
    }
}
