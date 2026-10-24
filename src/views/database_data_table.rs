// Displays bounded, read-only SQLite pages with native columns and scrolling.
use super::*;

pub(in crate::ui) struct DatabaseTable {
    workspace: WeakEntity<Workspace>,
    pub(super) columns: Vec<String>,
    pub(super) location: Option<(PathBuf, String, usize)>,
}

impl DatabaseTable {
    pub(in crate::ui) fn new(workspace: WeakEntity<Workspace>) -> Self {
        Self {
            workspace,
            columns: Vec::new(),
            location: None,
        }
    }
}

impl TableDelegate for DatabaseTable {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }
    fn rows_count(&self, cx: &App) -> usize {
        self.workspace
            .upgrade()
            .and_then(|workspace| {
                workspace
                    .read(cx)
                    .database_view
                    .as_ref()
                    .and_then(|page| page.as_ref().ok())
                    .map(|page| page.rows.len())
            })
            .unwrap_or(0)
    }
    fn column(&self, col: usize, _: &App) -> DataColumn {
        DataColumn::new(format!("sqlite-{col}"), self.columns[col].clone())
            .width(px(180.))
            .movable(false)
    }
    fn render_td(
        &mut self,
        row: usize,
        col: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div()
            .text_xs()
            .whitespace_nowrap()
            .overflow_hidden()
            .child(SelectableText::new(
                ("database-cell", row * self.columns.len() + col),
                self.cell_text(row, col, cx),
            ))
    }
    fn cell_text(&self, row: usize, col: usize, cx: &App) -> String {
        let Some(workspace) = self.workspace.upgrade() else {
            return String::new();
        };
        workspace
            .read(cx)
            .database_view
            .as_ref()
            .and_then(|page| page.as_ref().ok())
            .and_then(|page| page.rows.get(row))
            .and_then(|row| row.get(col))
            .cloned()
            .unwrap_or_default()
    }
    fn render_empty(
        &mut self,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div()
            .p_4()
            .text_sm()
            .child("This database table has no rows.")
    }
}
