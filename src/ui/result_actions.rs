// Loads result selections, queries, and bookmarks.
use super::*;

impl Workspace {
    pub(super) fn group_runs(&self, group: ArtifactGroup) -> Vec<String> {
        let Some(case) = &self.case else {
            return vec![];
        };
        case.document
            .runs
            .iter()
            .rev()
            .filter(|r| {
                Some(&r.evidence_id) == self.selected_evidence.as_ref()
                    && r.status == RunStatus::Completed
                    && ArtifactGroup::for_plugin(&r.plugin) == group
            })
            .map(|r| r.id.clone())
            // The report is a complete source snapshot. Older interpretations remain in history.
            .take(
                if matches!(group, ArtifactGroup::Downloads | ArtifactGroup::Quarantine) {
                    1
                } else {
                    usize::MAX
                },
            )
            .collect()
    }
    pub(super) fn select_evidence(
        &mut self,
        id: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.remember_location(cx);
        self.selected_evidence = Some(id);
        self.file_offset_physical = false;
        self.sync_os();
        self.selected = None;
        self.selected_row = None;
        self.selected_run = None;
        self.scope.clear();
        self.index = ResultIndex::default();
        self.set_scope(
            self.group_runs(self.browser_group),
            self.browser_group.label().into(),
            window,
            cx,
        );
    }
    pub(super) fn choose_group(
        &mut self,
        group: ArtifactGroup,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.remember_location(cx);
        self.browser_group = group;
        let runs = self.group_runs(group);
        self.set_scope(runs, group.label().into(), window, cx);
        if group == ArtifactGroup::Quarantine {
            self.refresh_passive_quarantine();
        }
    }
    pub(super) fn select_run(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        let Some(run) = self
            .case
            .as_ref()
            .and_then(|c| c.document.runs.iter().find(|r| r.id == id))
            .cloned()
        else {
            return;
        };
        self.remember_location(cx);
        if run.plugin == volgui::analysis::APPLICATION {
            self.browser_group = ArtifactGroup::Applications;
        }
        if run.plugin == volgui::analysis::APPLICATION
            && let Ok(pid) = volgui::analysis::application::target_pid(&run.arguments)
        {
            self.application_pid
                .update(cx, |input, cx| input.set_value(pid.to_string(), window, cx));
        }
        if run.plugin == volgui::analysis::registry::PRINT_KEY {
            let path = run
                .arguments
                .windows(2)
                .find(|a| a[0] == "--key")
                .map(|a| a[1].clone())
                .unwrap_or_default();
            self.registry_key
                .update(cx, |input, cx| input.set_value(path, window, cx));
        }
        if Some(&run.evidence_id) != self.selected_evidence.as_ref() {
            self.selected_evidence = Some(run.evidence_id.clone());
            self.file_offset_physical = false;
            self.sync_os();
        }
        let open_memory = run.plugin == volgui::analysis::APPLICATION
            && run.status == RunStatus::Completed
            && volgui::analysis::application::target_pid(&run.arguments).is_ok();
        let label = if run.plugin == volgui::analysis::APPLICATION {
            volgui::analysis::application::target_pid(&run.arguments)
                .map(|pid| format!("Process memory · PID {pid}"))
                .unwrap_or_else(|_| "Process Memory".into())
        } else if run.plugin == volgui::analysis::QUARANTINE {
            ArtifactGroup::Quarantine.label().into()
        } else {
            run.plugin
        };
        self.set_scope(vec![id], label, window, cx);
        if open_memory {
            self.open_application_dump(cx);
        }
    }
    pub(super) fn set_scope(
        &mut self,
        runs: Vec<String>,
        label: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let was_application = self.result_group() == Some(ArtifactGroup::Applications);
        self.network = volgui::network::Graph::default();
        *self.network_cache.borrow_mut() = Default::default();
        self.network_focus = None;
        self.network_endpoint = None;
        self.network_protocol = None;
        self.network_state = None;
        self.network_interesting = false;
        self.network_all_sources = false;
        self.network_sidebar_page = 0;
        self.column_filters.clear();
        self.scope = runs;
        if !was_application && self.result_group() == Some(ArtifactGroup::Applications) {
            self.content_sidebar_visible = true;
            self.content_encoding = volgui::extracted_files::ContentEncoding::Utf8;
        }
        self.selection_epoch += 1;
        self.relation_epoch += 1;
        self.relations = ProcessRelations::default();
        self.scope_label = label;
        if self.result_group() == Some(ArtifactGroup::Network) {
            self.content_sidebar_visible = true;
        }
        self.selected = None;
        self.selected_row = None;
        self.selected_run = self.scope.first().cloned();
        self.sort = None;
        self.index = ResultIndex::default();
        self.result_tree = ResultTree::default();
        self.row_cache.clear();
        self.file_recovery_states.clear();
        self.file_recovery = None;
        self.detail = DetailTab::Overview;
        self.reset_hex();
        self.handles = None;
        self.handles_loading = false;
        self.handle_epoch += 1;
        self.view = View::Workspace;
        self.query.update(cx, |s, cx| s.set_value("", window, cx));
        self.query_due = None;
        self.result_scroll = UniformListScrollHandle::default();
        self.reset_result_table(cx);
        self.start_query(cx);
        cx.notify();
    }
    pub(super) fn active_query(&self, cx: &App) -> Query {
        Query {
            filters: if matches!(
                self.result_group(),
                Some(ArtifactGroup::Web | ArtifactGroup::Downloads | ArtifactGroup::Quarantine)
            ) {
                self.column_filters.clone()
            } else {
                Default::default()
            },
            runs: self.scope.clone(),
            text: self.query.read(cx).value().to_string(),
            sort: self.sort.clone(),
        }
    }
    pub(super) fn start_query(&mut self, cx: &mut Context<Self>) {
        let Some(store) = self.store() else {
            return;
        };
        let query = self.active_query(cx);
        let group = self.result_group();
        let mut network_query = query.clone();
        if group == Some(ArtifactGroup::Network)
            && self.scope_label == ArtifactGroup::Network.label()
        {
            // Existing cases retain the original download run and offsets as provenance.
            // network_ids selects only payload configurations from those historical reports.
            if let Some(case) = &self.case {
                network_query.runs.extend(
                    case.document
                        .runs
                        .iter()
                        .filter(|run| {
                            Some(&run.evidence_id) == self.selected_evidence.as_ref()
                                && run.status == RunStatus::Completed
                                && run.plugin == volgui::analysis::DOWNLOADS
                        })
                        .map(|run| run.id.clone()),
                );
            }
        }
        let file_context = self
            .case
            .as_ref()
            .filter(|_| matches!(group, Some(ArtifactGroup::Files | ArtifactGroup::Processes)))
            .map(|case| (case.directory.clone(), case.document.clone()));
        let physical = self.file_offset_physical;
        let show_unavailable = self.show_unavailable_files;
        let file_runs: Vec<_> = if group == Some(ArtifactGroup::Processes) && self.show_file_handles
        {
            self.group_runs(ArtifactGroup::Files)
                .into_iter()
                .filter(|id| {
                    self.case.as_ref().is_some_and(|case| {
                        case.document.runs.iter().any(|run| {
                            &run.id == id
                                && matches!(
                                    run.plugin.as_str(),
                                    "windows.handles.Handles" | "linux.lsof.Lsof" | "mac.lsof.Lsof"
                                )
                        })
                    })
                })
                .collect()
        } else {
            vec![]
        };
        let epoch = self.query_epoch.fetch_add(1, Ordering::Relaxed) + 1;
        let token = self.query_epoch.clone();
        self.loading = true;
        self.network_loading = group == Some(ArtifactGroup::Network);
        self.inflight.clear();
        let tx = self.tx.clone();
        thread::spawn(move || {
            if token.load(Ordering::Relaxed) != epoch {
                return;
            }
            let result = store.query(&query).and_then(|mut index| {
                let recovery = file_context
                    .as_ref()
                    .map(|(directory, document)| {
                        volgui::analysis::files::RecoveryIndex::load(directory, document)
                    })
                    .transpose()?;
                let mut file_states = HashMap::new();
                let tree = match group {
                    Some(ArtifactGroup::Processes) => {
                        let mut files = store.tree_entries(&file_runs)?;
                        if let Some(recovery) = &recovery {
                            (files, file_states) = volgui::analysis::files::filter_entries(
                                &store,
                                recovery,
                                files,
                                physical,
                                show_unavailable,
                            )?;
                        }
                        let file_matches = store.query(&Query {
                            runs: file_runs,
                            text: query.text.clone(),
                            sort: None,
                            ..Default::default()
                        })?;
                        let mut matches = index.ids.clone();
                        matches.extend(file_matches.ids);
                        let tree = ResultTree::processes_with_files(
                            store.tree_entries(&query.runs)?,
                            files,
                            &matches,
                        );
                        let mut seen: HashSet<_> = index.ids.iter().copied().collect();
                        for (i, _) in &tree.visible {
                            if matches!(
                                tree.nodes[*i].kind,
                                volgui::result_tree::TreeNodeKind::File
                            ) && let Some(id) = tree.nodes[*i].record_id
                                && seen.insert(id)
                            {
                                index.ids.push(id);
                            }
                        }
                        tree
                    }
                    Some(ArtifactGroup::Files) => {
                        let mut files = store.tree_entries(&query.runs)?;
                        if let Some(recovery) = &recovery {
                            (files, file_states) = volgui::analysis::files::filter_entries(
                                &store,
                                recovery,
                                files,
                                physical,
                                show_unavailable,
                            )?;
                        }
                        let visible: HashSet<_> = files.iter().map(|entry| entry.id).collect();
                        index.ids.retain(|id| visible.contains(id));
                        ResultTree::files(files, &index.ids)
                    }
                    Some(ArtifactGroup::Registry) => {
                        ResultTree::registry(store.registry_entries(&query.runs)?, &index.ids)
                    }
                    Some(ArtifactGroup::Modules) => {
                        ResultTree::modules(store.module_entries(&query.runs)?, &index.ids)
                    }
                    _ => ResultTree::default(),
                };
                let mut ids: Vec<_> = if tree.nodes.is_empty() {
                    index.ids.iter().take(128).copied().collect()
                } else {
                    tree.visible
                        .iter()
                        .filter_map(|(i, _)| tree.nodes[*i].record_id)
                        .take(128)
                        .collect()
                };
                if let Some(id) = index.ids.first()
                    && !ids.contains(id)
                {
                    ids.push(*id);
                }
                let rows = store.fetch_enriched(&ids)?;
                Ok(QueryResult {
                    index,
                    rows,
                    tree,
                    file_states,
                    recovery,
                })
            });
            let _ = tx.send(Event::Indexed(epoch, result));
            if group == Some(ArtifactGroup::Network) {
                let graph = volgui::network::Graph::load(&store, &network_query, epoch, &token);
                let _ = tx.send(Event::NetworkLoaded(epoch, graph));
            }
        });
        cx.notify();
    }
    pub(super) fn request_rows(&mut self, range: Range<usize>) {
        let ids = self
            .index
            .ids
            .get(range.start.min(self.index.ids.len())..range.end.min(self.index.ids.len()))
            .unwrap_or(&[])
            .to_vec();
        self.request_record_ids(ids);
    }
    pub(super) fn request_record_ids(&mut self, ids: Vec<i64>) {
        let Some(store) = self.store() else {
            return;
        };
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|id| !self.row_cache.contains_key(id) && !self.inflight.contains(id))
            .take(256)
            .collect();
        if ids.is_empty() {
            return;
        }
        self.inflight.extend(&ids);
        let epoch = self.query_epoch.load(Ordering::Relaxed);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = store.fetch_enriched(&ids);
            let _ = tx.send(Event::Rows(epoch, ids, result));
        });
    }
    pub(super) fn load_record(&mut self, id: i64, cx: &mut Context<Self>) {
        let Some(store) = self.store() else {
            return;
        };
        if self.selected.as_ref().is_none_or(|r| r.id != id) {
            self.remember_location(cx);
        }
        self.selection_epoch += 1;
        let epoch = self.selection_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Selected(
                epoch,
                store.fetch_enriched(&[id]).map(|mut r| r.pop()),
            ));
        });
    }
    pub(super) fn open_process(&mut self, pid: String, cx: &mut Context<Self>) {
        let Some(store) = self.store() else {
            return;
        };
        self.remember_location(cx);
        self.selection_epoch += 1;
        let epoch = self.selection_epoch;
        let mut runs = self.group_runs(ArtifactGroup::Processes);
        runs.sort_by_key(|id| {
            self.case
                .as_ref()
                .and_then(|c| c.document.runs.iter().find(|r| &r.id == id))
                .is_none_or(|r| !r.plugin.ends_with("pslist.PsList"))
        });
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result=store.process_record(&runs,&pid).and_then(|record| match record {
                Some(record)=>Ok(Some(record)),
                None=>Err(format!("PID {pid} is not uniquely present in the collected process inventories. Collect processes or inspect the network record's source; the process may have exited or its PID may have been reused.")),
            });
            let _ = tx.send(Event::Selected(epoch, result));
        });
    }
    pub(super) fn load_annotation(
        &mut self,
        run: String,
        row: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(store) = self.store() else {
            return;
        };
        self.select_run(run.clone(), window, cx);
        self.selection_epoch += 1;
        let epoch = self.selection_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Selected(
                epoch,
                store.record(&run, row).and_then(|record| match record {
                    Some(record) => store
                        .fetch_enriched(&[record.id])
                        .map(|mut rows| rows.pop()),
                    None => Ok(None),
                }),
            ));
        });
    }
    pub(super) fn show_record(
        &mut self,
        record: StoredRecord,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.reset_hex();
        self.handles = None;
        self.handles_loading = false;
        self.handle_epoch += 1;
        self.selected_run = Some(record.run_id.clone());
        self.selected_row = Some(record.row);
        self.selected = Some(Arc::new(record));
        if self.result_group() == Some(ArtifactGroup::Network)
            && self.detail == DetailTab::SourceBytes
        {
            self.load_network_bytes(cx);
        }
        if self.result_group() == Some(ArtifactGroup::Applications) {
            let row = &self.selected.as_ref().unwrap().record;
            self.content_encoding = match row.text("Encoding").as_str() {
                "UTF-16LE" => volgui::extracted_files::ContentEncoding::Utf16Le,
                "UTF-16BE" => volgui::extracted_files::ContentEncoding::Utf16Be,
                _ => volgui::extracted_files::ContentEncoding::Utf8,
            };
            let pid = row.text("PID");
            self.application_pid
                .update(cx, |input, cx| input.set_value(pid, window, cx));
            self.application_text_scroll.set_offset(Point::default());
        }
        if self.detail == DetailTab::Handles {
            self.load_handles(0, cx);
        }
        self.hex_scroll.set_offset(Point::default());
        if self.result_group() != Some(ArtifactGroup::Network)
            && (self.content_sidebar_visible
                || self.result_group() == Some(ArtifactGroup::Applications))
        {
            self.load_hex(cx);
        }
        self.raw_expanded.clear();
        self.details_scroll.set_offset(Point::default());
        self.relation_epoch += 1;
        self.relations = ProcessRelations::default();
        if let Some(pid) = self.selected.as_ref().and_then(|r| {
            ["PID", "Pid", "pid"]
                .iter()
                .find_map(|name| r.record.fields.get(*name).map(display_value))
        }) && let Some(store) = self.store()
        {
            let mut runs = self.group_runs(ArtifactGroup::Processes);
            runs.sort_by_key(|id| {
                self.case
                    .as_ref()
                    .and_then(|c| c.document.runs.iter().find(|r| &r.id == id))
                    .is_none_or(|r| !r.plugin.ends_with("pslist.PsList"))
            });
            let epoch = self.relation_epoch;
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Event::Relations(
                    epoch,
                    store.process_relations(&runs, &pid),
                ));
            });
        }
        cx.notify();
    }
    pub(super) fn toggle_bookmark(&mut self, cx: &mut Context<Self>) {
        let (Some(c), Some(run), Some(row)) =
            (&mut self.case, &self.selected_run, self.selected_row)
        else {
            return;
        };
        let marked = c.annotation(run, row).is_some_and(|a| a.bookmarked);
        let note = c
            .annotation(run, row)
            .map(|a| a.note.clone())
            .unwrap_or_default();
        if let Err(e) = c.annotate(run, row, !marked, note) {
            self.error = Some(e);
        } else {
            self.message = "Bookmark updated".into();
        }
        cx.notify();
    }
}
