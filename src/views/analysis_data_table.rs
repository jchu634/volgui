// Renders grouped analysis choices in a native data table.
use super::*;
use std::rc::Rc;

#[derive(Clone)]
pub(super) enum AnalysisRow {
    Extended,
    Group {
        group: ArtifactGroup,
        expanded: bool,
        count: usize,
        selected_count: usize,
        ids: Vec<String>,
    },
    Plugin {
        id: String,
        description: String,
        blocked: bool,
        previous: bool,
        indented: bool,
    },
}

pub(in crate::ui) struct AnalysisTable {
    workspace: WeakEntity<Workspace>,
    pub(super) rows: Vec<AnalysisRow>,
    pub(super) visible_ids: Vec<String>,
    pub(super) range_ids: Rc<Vec<String>>,
}

impl AnalysisTable {
    pub(in crate::ui) fn new(workspace: WeakEntity<Workspace>) -> Self {
        Self {
            workspace,
            rows: Vec::new(),
            visible_ids: Vec::new(),
            range_ids: Rc::default(),
        }
    }
}

impl TableDelegate for AnalysisTable {
    fn columns_count(&self, _: &App) -> usize {
        5
    }
    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }
    fn column(&self, col: usize, _: &App) -> DataColumn {
        let (key, label, width) = [
            ("selected", "", 40.),
            ("analysis", "Analysis", 240.),
            ("plugin", "Plugin", 240.),
            ("level", "Level", 80.),
            ("options", "Options", 170.),
        ][col];
        DataColumn::new(key, label)
            .width(px(width))
            .movable(false)
            .resizable(col != 0)
    }

    fn render_th(
        &mut self,
        col: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        if col != 0 {
            return div()
                .text_xs()
                .child(self.column(col, cx).name)
                .into_any_element();
        }
        let ids = self.visible_ids.clone();
        self.workspace
            .update(cx, |workspace, cx| {
                let checked = !ids.is_empty()
                    && workspace
                        .analysis_drafts
                        .get(workspace.analysis_active)
                        .is_some_and(|draft| ids.iter().all(|id| draft.selected.contains(id)));
                Checkbox::new("select-visible-analyses")
                    .accessibility_label("Select all visible analyses")
                    .checked(checked)
                    .disabled(ids.is_empty())
                    .on_change(cx.listener(move |workspace, checked, _, cx| {
                        workspace.select_analysis_ids(&ids, *checked, cx)
                    }))
                    .into_any_element()
            })
            .unwrap_or_else(|_| div().into_any_element())
    }

    fn render_tr(
        &mut self,
        row: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let element = div().id(("analysis-row", row));
        match &self.rows[row] {
            AnalysisRow::Extended => element.bg(cx.theme().muted),
            AnalysisRow::Group { ids, .. } => element.when(ids.is_empty(), |row| row.opacity(0.45)),
            AnalysisRow::Plugin { id, blocked, .. } => {
                let focused = self
                    .workspace
                    .upgrade()
                    .is_some_and(|workspace| workspace.read(cx).plugin.as_ref() == Some(id));
                element
                    .when(*blocked, |row| row.opacity(0.45))
                    .when(focused, |row| row.bg(cx.theme().accent))
            }
        }
    }

    fn render_td(
        &mut self,
        row: usize,
        col: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = self.rows[row].clone();
        let range_ids = self.range_ids.clone();
        self.workspace
            .update(cx, |workspace, cx| {
                workspace.render_analysis_cell(row, col, range_ids, cx)
            })
            .unwrap_or_else(|_| div().into_any_element())
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div()
            .p_4()
            .text_sm()
            .child("No matching analyses. Try showing extended analyses or changing the search.")
    }
}

impl Workspace {
    fn select_analysis_ids(&mut self, ids: &[String], checked: bool, cx: &mut Context<Self>) {
        if let Some(draft) = self.analysis_drafts.get_mut(self.analysis_active) {
            for id in ids {
                if checked {
                    draft.selected.insert(id.clone());
                } else {
                    draft.selected.remove(id);
                }
            }
        }
        self.analysis_error = None;
        cx.notify();
    }

    fn render_analysis_cell(
        &self,
        row: AnalysisRow,
        col: usize,
        range_ids: Rc<Vec<String>>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let cell = div().text_xs().min_w_0().truncate();
        match row {
            AnalysisRow::Extended => cell
                .font_weight(FontWeight::SEMIBOLD)
                .child(if col == 1 { "Extended" } else { "" })
                .into_any_element(),
            AnalysisRow::Group {
                group,
                expanded,
                count,
                selected_count,
                ids,
            } => match col {
                0 => Checkbox::new(key("select-analysis-group", group.label()))
                    .accessibility_label(format!("Select {} analyses", group.label()))
                    .checked(selected_count > 0)
                    .disabled(ids.is_empty())
                    .on_change(cx.listener(move |workspace, checked, _, cx| {
                        workspace.select_analysis_ids(&ids, *checked, cx)
                    }))
                    .into_any_element(),
                1 => cell.child(group.label()).into_any_element(),
                2 => cell
                    .text_color(cx.theme().muted_foreground)
                    .child("Multiple")
                    .into_any_element(),
                3 => cell
                    .text_color(cx.theme().muted_foreground)
                    .child("Basic")
                    .into_any_element(),
                _ => div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(cell.child(format!("{selected_count}/{count} selected")))
                    .child(
                        Button::new(key("analysis-group", group.label()))
                            .xsmall()
                            .ghost()
                            .icon(if expanded {
                                IconName::ChevronDown
                            } else {
                                IconName::ChevronRight
                            })
                            .tooltip(format!(
                                "Show individual {} analyses ({selected_count}/{count} selected)",
                                group.label()
                            ))
                            .on_click(cx.listener(move |workspace, _, _, cx| {
                                if !workspace.analysis_collapsed_groups.remove(&group) {
                                    workspace.analysis_collapsed_groups.insert(group);
                                }
                                cx.notify();
                            })),
                    )
                    .into_any_element(),
            },
            AnalysisRow::Plugin {
                id,
                description,
                blocked,
                previous,
                indented,
            } => match col {
                0 => {
                    let checked = self
                        .analysis_drafts
                        .get(self.analysis_active)
                        .is_some_and(|draft| draft.selected.contains(&id));
                    Checkbox::new(key("select-analysis", &id))
                        .accessibility_label(format!("Select {id}"))
                        .checked(checked)
                        .disabled(blocked)
                        .on_change(cx.listener(move |workspace, checked, window, cx| {
                            if let Some(draft) =
                                workspace.analysis_drafts.get_mut(workspace.analysis_active)
                            {
                                draft.select(&id, *checked, window.modifiers().shift, &range_ids);
                            }
                            workspace.analysis_error = None;
                            cx.notify();
                        }))
                        .into_any_element()
                }
                1 => {
                    let label = basic_label(&id)
                        .map(str::to_owned)
                        .unwrap_or_else(|| id.rsplit('.').next().unwrap_or(&id).to_string());
                    let description = if previous {
                        format!(
                            "{description} Completed, queued, or running for this evidence. Enable Allow previously run plugins to select it again."
                        )
                    } else {
                        description
                    };
                    cell.id(key("analysis-label", &id))
                        .when(indented, |cell| cell.pl_4())
                        .child(label)
                        .tooltip(move |window, cx| {
                            Tooltip::new(description.clone()).build(window, cx)
                        })
                        .into_any_element()
                }
                2 => cell
                    .text_color(cx.theme().muted_foreground)
                    .child(id)
                    .into_any_element(),
                3 => cell
                    .text_color(cx.theme().muted_foreground)
                    .child(if basic_label(&id).is_some() {
                        "Basic"
                    } else {
                        "Extended"
                    })
                    .into_any_element(),
                _ => Button::new(key("analysis-options", &id))
                    .xsmall()
                    .ghost()
                    .label("Options")
                    .tooltip(format!("Options for {id}"))
                    .on_click(cx.listener(move |workspace, _, window, cx| {
                        workspace.focus_plugin(id.clone(), window, cx)
                    }))
                    .into_any_element(),
            },
        }
    }
}
