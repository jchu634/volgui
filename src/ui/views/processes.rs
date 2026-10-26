// Renders processes beneath their parents with aligned record details.
use super::*;

impl Workspace {
    pub(in crate::ui) fn render_processes(&self, cx: &mut Context<Self>) -> AnyElement {
        self.render_artifact_tree(ArtifactGroup::Processes, cx)
    }
}
