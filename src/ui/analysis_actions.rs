// Configures, queues, and runs analyses.
use super::*;

impl Workspace {
    pub(super) fn plugin_help(&mut self, cx: &mut Context<Self>) {
        if self.is_working() {
            return;
        }
        let (Some(engine), Some(plugin)) = (self.installation.clone(), self.plugin.clone()) else {
            return;
        };
        let cancel = self.start("Loading plugin options");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = if plugin == volgui::investigation::BROWSER || plugin == volgui::analyses::REGISTRY_ALL {
                Ok("This analysis accepts no custom options. Select its checkbox to queue it.".into())
            } else {
                engine.help(&plugin, &cancel)
            };
            let _ = tx.send(Event::Help(plugin, result));
        });
        cx.notify();
    }

    pub(super) fn save_plugin_arguments(&mut self, cx: &App) {
        if let Some(id) = self.plugin.clone()
            && let Some(draft) = self.analysis_drafts.get_mut(self.analysis_active)
        {
            draft
                .arguments
                .insert(id, self.arguments.read(cx).value().to_string());
        }
    }
    pub(super) fn focus_plugin(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        self.save_plugin_arguments(cx);
        let value = self
            .analysis_drafts
            .get(self.analysis_active)
            .and_then(|d| d.arguments.get(&id))
            .cloned()
            .unwrap_or_default();
        self.plugin = Some(id);
        self.plugin_help.clear();
        self.arguments
            .update(cx, |s, cx| s.set_value(value, window, cx));
        cx.notify();
    }
    pub(super) fn select_analysis_evidence(
        &mut self,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.save_plugin_arguments(cx);
        self.analysis_active = index;
        self.plugin = None;
        self.plugin_help.clear();
        self.analysis_error = None;
        self.arguments
            .update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }
    pub(super) fn set_os(
        &mut self,
        os: OperatingSystem,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.save_plugin_arguments(cx);
        if let Some(draft) = self.analysis_drafts.get_mut(self.analysis_active) {
            draft.set_os(os);
        }
        self.plugin = None;
        self.plugin_help.clear();
        self.analysis_error = None;
        self.arguments
            .update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }
    pub(super) fn queue_analyses(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        self.save_plugin_arguments(cx);
        let result = (|| {
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure Volatility in settings")?;
            let case = self.case.as_ref().ok_or("Open a case first")?;
            let mut runs = Vec::new();
            for draft in &self.analysis_drafts {
                if !self.allow_previous_plugins
                    && draft.selected.iter().any(|id| {
                        case.document.runs.iter().any(|run| {
                            run.status.blocks_plugin_selection()
                                && run.evidence_id == draft.evidence_id
                                && &run.plugin == id
                        })
                    })
                {
                    return Err(
                        "Enable Allow previously run plugins to queue a previous analysis".into(),
                    );
                }
                let evidence = case
                    .document
                    .evidence
                    .iter()
                    .find(|e| e.id == draft.evidence_id)
                    .ok_or("Evidence is no longer available")?;
                runs.extend(
                    draft
                        .prepare_in_case(engine, evidence, case)
                        .map_err(|error| format!("{}: {error}", evidence.name()))?,
                );
            }
            if runs.is_empty() {
                return Err("Select at least one analysis".into());
            }
            let count = runs.len();
            let case = self.case.as_mut().unwrap();
            let previous_os: Vec<_> = case
                .document
                .evidence
                .iter()
                .map(|e| e.operating_system)
                .collect();
            for draft in &self.analysis_drafts {
                if let Some(evidence) = case
                    .document
                    .evidence
                    .iter_mut()
                    .find(|e| e.id == draft.evidence_id)
                {
                    evidence.operating_system = draft.os;
                }
            }
            if let Err(error) = case.queue_batch(runs) {
                for (evidence, os) in case.document.evidence.iter_mut().zip(previous_os) {
                    evidence.operating_system = os;
                }
                return Err(error);
            }
            Ok::<_, String>(count)
        })();
        match result {
            Ok(count) => {
                if self.batch_total == self.batch_finished {
                    self.batch_total = 0;
                    self.batch_finished = 0;
                }
                self.batch_total += count;
                self.message = format!("Queued {count} analyses");
                self.analysis_error = None;
                self.sync_os();
                window.close_dialog(cx);
                self.start_next(window, cx);
                self.view = View::Workspace;
            }
            Err(error) => self.analysis_error = Some(error),
        }
        cx.notify();
    }
    pub(super) fn dump_file(
        &mut self,
        open_in_imhex: bool,
        show_hex: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.busy.is_some() {
            return;
        }
        let result = (|| {
            let executable = if open_in_imhex {
                Some(volgui::extracted_files::imhex().ok_or(
                    "ImHex was not found. Install it in its default location or add it to PATH.",
                )?)
            } else {
                None
            };
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure Volatility in settings")?;
            let record = self.selected.as_ref().ok_or("Select a file first")?;
            let case = self.case.as_mut().ok_or("Open a case first")?;
            let id = volgui::extracted_files::queue_file_dump(
                case,
                engine,
                record,
                self.file_offset_physical,
            )?;
            Ok::<_, String>((
                id,
                FileDumpRequest {
                    record_id: record.id,
                    selection_epoch: self.selection_epoch,
                    executable,
                    show_hex,
                },
            ))
        })();
        match result {
            Ok((id, request)) => {
                self.file_dumps.insert(id, request);
                if self.batch_total == self.batch_finished {
                    self.batch_total = 0;
                    self.batch_finished = 0;
                }
                self.batch_total += 1;
                self.message = "Queued selected file for extraction".into();
                self.start_next(window, cx);
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }
    pub(super) fn finish_file_dump(&mut self, id: &str, executable: Option<PathBuf>) {
        let Some(case) = &self.case else { return };
        match volgui::extracted_files::list(&case.run_dir(id)) {
            Ok(files) if files.is_empty() => {
                self.error = Some("No cached file contents could be extracted from memory. See Run details for diagnostics.".into());
            }
            Ok(files) => {
                if let Some(executable) = executable {
                    for file in &files {
                        if let Err(error) = volgui::extracted_files::open(&executable, file) {
                            self.error = Some(format!(
                                "File extracted, but ImHex could not open it: {error}"
                            ));
                            return;
                        }
                    }
                    self.message = format!("Opened {} extracted file(s) in ImHex", files.len());
                } else {
                    self.message = format!(
                        "Extracted {} file(s). Use Save as... to export them.",
                        files.len()
                    );
                }
            }
            Err(error) => self.error = Some(format!("Could not list extracted files: {error}")),
        }
    }
    pub(super) fn retry_run(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.retry_runs(&[id.to_string()], window, cx);
    }
    pub(super) fn retry_all_failed(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ids: Vec<_> = self
            .case
            .iter()
            .flat_map(|case| case.document.queue_runs())
            .filter(|run| matches!(run.status, RunStatus::Failed | RunStatus::Interrupted))
            .map(|run| run.id.clone())
            .collect();
        if !ids.is_empty() {
            self.retry_runs(&ids, window, cx);
        }
    }
    pub(super) fn retry_runs(
        &mut self,
        ids: &[String],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = (|| {
            let case = self.case.as_mut().ok_or("Open a case first")?;
            queue_retries_with_engine(case, self.installation.as_ref(), ids)
        })();
        match result {
            Ok(count) => {
                if self.batch_total == self.batch_finished {
                    self.batch_total = 0;
                    self.batch_finished = 0;
                }
                self.batch_total += count;
                self.message = if count == 1 {
                    "Retry queued as a new analysis".into()
                } else {
                    format!("Queued {count} retries as new analyses")
                };
                self.start_next(window, cx);
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }
    pub(super) fn remove_queue_run(&mut self, id: &str, cx: &mut Context<Self>) {
        if let Some(case) = self.case.as_mut()
            && let Err(error) = case.remove_queue_run(id)
        {
            self.error = Some(error);
        }
        cx.notify();
    }
    pub(super) fn clear_queue(&mut self, scope: QueueClearScope, cx: &mut Context<Self>) {
        self.browser_recovery_pending = false;
        let Some(case) = self.case.as_mut() else {
            return;
        };
        match case.clear_queue(scope) {
            Ok(count) => {
                self.queue_scroll.set_offset(point(px(0.), px(0.)));
                self.message = format!("Cleared {count} jobs from the queue");
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }
    pub(super) fn start_next(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.queue_paused {
            return;
        }
        loop {
            let engine = self.installation.clone();
            let Some(case) = &mut self.case else {
                return;
            };
            let Some(i) = volgui::analyses::next_queued_run(
                &case.document.runs,
                self.settings.max_concurrent_jobs,
            ) else {
                if self.browser_recovery_pending && self.running.is_empty() && !self.has_queued() {
                    self.browser_recovery_pending = false;
                    self.prepare_browser_recovery(cx);
                }
                return;
            };
            let native = volgui::investigation::is_native(&case.document.runs[i].plugin);
            if !native && engine.is_none() {
                return;
            }
            let evidence = case
                .document
                .evidence
                .iter()
                .find(|e| e.id == case.document.runs[i].evidence_id)
                .unwrap();
            if let Err(e) = evidence.check_metadata() {
                self.file_dumps.remove(&case.document.runs[i].id);
                case.document.runs[i].status = RunStatus::Failed;
                case.document.runs[i].message = e.clone();
                case.document.runs[i].finished_at = Some(now());
                self.error = Some(e);
                if let Err(e) = case.save() {
                    self.error = Some(e);
                    self.queue_paused = true;
                }
                self.batch_finished += 1;
                cx.notify();
                if self.queue_paused {
                    return;
                }
                continue;
            }
            case.document.runs[i].status = RunStatus::Running;
            case.document.runs[i].started_at = Some(now());
            if let Err(e) = case.save() {
                case.document.runs[i].status = RunStatus::Queued;
                case.document.runs[i].started_at = None;
                self.error = Some(e);
                self.queue_paused = true;
                return;
            }
            let run = case.document.runs[i].clone();
            let directory = case.run_dir(&run.id);
            let store = ResultStore::at(&case.directory);
            let case_directory = case.directory.clone();
            let document = case.document.clone();
            let cancel = Arc::new(AtomicBool::new(false));
            let label = format!("Running {}", run.plugin);
            self.running.insert(
                run.id.clone(),
                Busy {
                    label: label.clone(),
                    cancel: cancel.clone(),
                    started: Instant::now(),
                    displayed_seconds: 0,
                },
            );
            self.message = label;
            let tx = self.tx.clone();
            thread::spawn(move || {
                let mut outcome = if native {
                    volgui::investigation::execute(
                        &case_directory,
                        &document,
                        &run,
                        &cancel,
                        |message| {
                            let _ = tx.send(Event::Progress(message));
                        },
                    )
                } else {
                    engine
                        .expect("engine checked before starting job")
                        .execute(&run, &directory, &cancel)
                };
                if let Some(table) = outcome.table.take()
                    && let Err(e) = store.insert_cancellable(&run, &table, &cancel)
                {
                    outcome.status = if cancel.load(Ordering::Relaxed) {
                        RunStatus::Cancelled
                    } else {
                        RunStatus::Failed
                    };
                    outcome.message =
                        format!("Could not save scan to SQLite: {e}. Raw output is retained.");
                }
                let _ = tx.send(Event::Finished(run.id, outcome));
            });
            cx.notify();
        }
    }
}
