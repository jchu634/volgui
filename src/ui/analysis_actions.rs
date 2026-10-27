// Configures, queues, and runs analyses.
use super::*;

impl Workspace {
    pub(super) fn rescan_case(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_working() || self.has_queued() {
            self.analysis_error =
                Some("Finish or cancel queued and running analyses before rescanning".into());
            cx.notify();
            return;
        }
        let Some(engine) = self.installation.clone() else {
            self.analysis_error = Some("Configure analysis engine in settings".into());
            cx.notify();
            return;
        };
        let Some(mut case) = self.case.take() else {
            return;
        };
        let cancel = self.start("Backing up and rebuilding case for rescan");
        self.query_epoch.fetch_add(1, Ordering::Relaxed);
        self.selection_epoch += 1;
        self.handle_epoch += 1;
        self.reset_file_listing();
        self.reset_hex();
        self.browser_recovery_pending = false;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = case.rescan(&engine, &cancel);
            let _ = tx.send(Event::Rescanned(case, result));
        });
        window.close_dialog(cx);
        cx.notify();
    }

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
            let result = if plugin == volgui::analysis::APPLICATION {
                Ok(volgui::analysis::application::HELP.into())
            } else if plugin == volgui::analysis::FILES {
                Ok("Collects FileScan and available file handles, attempts each distinct file object and records recovery outcomes. Cached contents may be partial. Use --physical only for older captures whose unlabelled FileScan offsets are physical. Other options are not accepted.".into())
            } else if plugin == volgui::analysis::NETWORK_ATTRIBUTION {
                Ok(volgui::analysis::network_attribution::HELP.into())
            } else if plugin == volgui::analysis::NETWORK {
                Ok("Collects available Windows network, process, command history and handle plugins, then correlates their saved records. Extracts IP-based share references, connection commands and credentials explicitly present in network drive commands. Recovers payload configurations from acquisition bytes and queues a separate process attribution job when supported. Attribution scans readable user VADs, reusing process dumps. Findings retain source run, row and field provenance. No custom arguments. Missing or failed source plugins are reported in Run details. Recovered text does not prove execution or a live connection.".into())
            } else if plugin == volgui::analysis::DOWNLOADS {
                Ok(volgui::analysis::downloads::HELP.into())
            } else if plugin == volgui::analysis::QUARANTINE {
                Ok(volgui::analysis::quarantine::HELP.into())
            } else if plugin == volgui::analysis::FILE_PATHS
                || plugin == volgui::analysis::BROWSER
                || plugin == volgui::analyses::REGISTRY_ALL
            {
                Ok(
                    "This analysis accepts no custom options. Select its checkbox to queue it."
                        .into(),
                )
            } else {
                engine.help(&plugin, &cancel)
            };
            let _ = tx.send(Event::Help(plugin, result));
        });
        cx.notify();
    }

    pub(super) fn save_plugin_arguments(&mut self, cx: &App) {
        if let Some(id) = self.plugin.clone()
            && id != volgui::analysis::APPLICATION
            && let Some(draft) = self.analysis_drafts.get_mut(self.analysis_active)
        {
            draft
                .arguments
                .insert(id, self.arguments.read(cx).value().to_string());
        }
    }
    pub(super) fn save_application_options(&mut self, cx: &mut Context<Self>) {
        let mut args = Vec::new();
        let pid = self
            .analysis_application_pid
            .read(cx)
            .value()
            .trim()
            .to_string();
        let contains = self
            .analysis_application_contains
            .read(cx)
            .value()
            .to_string();
        if !pid.is_empty() {
            args.extend(["--pid".into(), pid]);
        }
        if !contains.is_empty() {
            args.extend(["--contains".into(), contains]);
        }
        if let Some(draft) = self.analysis_drafts.get_mut(self.analysis_active) {
            draft.arguments.insert(
                volgui::analysis::APPLICATION.into(),
                volgui::volatility::format_arguments(&args),
            );
        }
        cx.notify();
    }
    pub(super) fn sync_application_options(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let args = self
            .analysis_drafts
            .get(self.analysis_active)
            .and_then(|draft| draft.arguments.get(volgui::analysis::APPLICATION))
            .and_then(|args| volgui::volatility::parse_arguments(args).ok())
            .unwrap_or_default();
        let value = |flag: &str| {
            args.windows(2)
                .find(|pair| pair[0] == flag)
                .map(|pair| pair[1].clone())
                .unwrap_or_default()
        };
        let pid = value("--pid");
        let contains = value("--contains");
        self.analysis_application_pid
            .update(cx, |input, cx| input.set_value(pid, window, cx));
        self.analysis_application_contains
            .update(cx, |input, cx| input.set_value(contains, window, cx));
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
        self.sync_application_options(window, cx);
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
                .ok_or("Configure analysis engine in settings")?;
            let case = self.case.as_ref().ok_or("Open a case first")?;
            let mut runs = Vec::new();
            for draft in &self.analysis_drafts {
                if !self.allow_previous_plugins
                    && draft.selected.iter().any(|id| {
                        case.document.runs.iter().any(|run| {
                            run.status.blocks_plugin_selection()
                                && !volgui::analysis::quarantine::is_passive(run)
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
                Some(self.imhex_path.clone().ok_or(
                    "ImHex was not found. Install it in its default location or add it to PATH.",
                )?)
            } else {
                None
            };
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine in settings")?;
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
        let directory = case.run_dir(id);
        let case_directory = case.directory.clone();
        let tx = self.tx.clone();
        self.message = if executable.is_some() {
            "Preparing extracted files for ImHex...".into()
        } else {
            "Loading extracted files...".into()
        };
        thread::spawn(move || {
            let result = (|| {
                let files = volgui::extracted_files::list(&directory)
                    .map_err(|error| format!("Could not list extracted files: {error}"))?;
                if files.is_empty() {
                    return Ok("No cached contents were recovered. This file is hidden when Show unavailable files is off. Run details retain the extraction diagnostics.".into());
                }
                if let Some(executable) = executable {
                    for file in &files {
                        volgui::extracted_files::open(&executable, file).map_err(|error| {
                            format!("File extracted, but ImHex could not open it: {error}")
                        })?;
                    }
                    Ok(format!("Opened {} extracted file(s) in ImHex", files.len()))
                } else {
                    Ok(format!(
                        "Extracted {} file(s). Use Save as... to export them.",
                        files.len()
                    ))
                }
            })();
            let _ = tx.send(Event::FileActionCompleted(case_directory, result));
        });
    }

    pub(super) fn retry_run(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.retry_runs(&[id.to_string()], window, cx);
    }
    pub(super) fn confirm_cancel_all(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.queue_open = false;
        cx.notify();
        let workspace = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, _, _| {
            let workspace = workspace.clone();
            dialog
                .width(px(460.))
                .title("Cancel all analyses?")
                .child("This will stop all running analyses and cancel all queued analyses. Finished jobs and saved results will be kept.")
                .footer(
                    div().flex().w_full().justify_end().gap_2()
                        .child(app_button("keep-queue-running").small().label("Keep running")
                            .on_click(|_, window, cx| window.close_dialog(cx)))
                        .child(app_button("confirm-cancel-all").small().primary().label("Cancel all")
                            .on_click(move |_, window, cx| {
                                window.close_dialog(cx);
                                let _ = workspace.update(cx, |this, cx| this.cancel_all_runs(cx));
                            })),
                )
        });
    }

    fn cancel_all_runs(&mut self, cx: &mut Context<Self>) {
        self.browser_recovery_pending = false;
        for running in self.running.values() {
            running.cancel.store(true, Ordering::Relaxed);
        }
        if let Some(case) = &mut self.case {
            for run in &mut case.document.runs {
                if run.status == RunStatus::Queued {
                    run.status = RunStatus::Cancelled;
                    run.finished_at = Some(now());
                    self.file_dumps.remove(&run.id);
                    self.batch_finished += 1;
                }
            }
            if let Err(error) = case.save() {
                self.error = Some(error);
            }
        }
        self.message = "Cancelling all analyses...".into();
        cx.notify();
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
                self.queue_scroll
                    .0
                    .borrow()
                    .base_handle
                    .set_offset(point(px(0.), px(0.)));
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
            let application_pending = case.document.runs[i].plugin == volgui::analysis::APPLICATION
                && case.document.runs[i].message == volgui::analyses::APPLICATION_RECOVERY_PENDING;
            let files_pending = case.document.runs[i].plugin == volgui::analysis::FILES
                && case.document.runs[i].message == volgui::analysis::files::PENDING;
            let downloads_pending = case.document.runs[i].plugin == volgui::analysis::DOWNLOADS
                && case.document.runs[i].message == volgui::analysis::downloads::PENDING;
            let quarantine_pending = case.document.runs[i].plugin == volgui::analysis::QUARANTINE
                && case.document.runs[i].message == volgui::analysis::quarantine::PENDING;
            let attribution_pending = case.document.runs[i].plugin
                == volgui::analysis::NETWORK_ATTRIBUTION
                && case.document.runs[i].message == volgui::analysis::network_attribution::PENDING;
            if attribution_pending
                || application_pending
                || files_pending
                || downloads_pending
                || quarantine_pending
                || case.document.runs[i].plugin == volgui::analysis::BROWSER
                    && case.document.runs[i].message == volgui::analyses::BROWSER_RECOVERY_PENDING
            {
                let Some(engine) = engine.as_ref() else {
                    return;
                };
                let prepared = if attribution_pending {
                    volgui::analyses::prepare_network_attribution(
                        case,
                        engine,
                        &case.document.runs[i],
                    )
                } else if application_pending {
                    volgui::analyses::prepare_application_recovery(
                        case,
                        engine,
                        &case.document.runs[i],
                    )
                } else if quarantine_pending {
                    volgui::analyses::prepare_quarantine_recovery(
                        case,
                        engine,
                        &case.document.runs[i],
                    )
                } else if downloads_pending {
                    volgui::analyses::prepare_download_recovery(
                        case,
                        engine,
                        &case.document.runs[i],
                    )
                } else if files_pending {
                    volgui::analyses::prepare_file_recovery(case, engine, &case.document.runs[i])
                } else {
                    volgui::analyses::prepare_browser_recovery(case, engine, &case.document.runs[i])
                };
                match prepared {
                    Ok(runs) => {
                        let previous = case.document.runs.clone();
                        case.document.runs[i].message.clear();
                        let replace = attribution_pending
                            || application_pending
                            || files_pending
                            || downloads_pending
                            || quarantine_pending;
                        let count = runs.len().saturating_sub(usize::from(replace));
                        if replace {
                            case.document.runs.splice(i..=i, runs);
                        } else {
                            case.document.runs.splice(i..i, runs);
                        }
                        if let Err(error) = case.save() {
                            case.document.runs = previous;
                            self.error = Some(error);
                            self.queue_paused = true;
                            return;
                        }
                        self.batch_total += count;
                        continue;
                    }
                    Err(error) => {
                        case.document.runs[i].status = RunStatus::Failed;
                        case.document.runs[i].message = error.clone();
                        case.document.runs[i].finished_at = Some(now());
                        self.error = Some(error);
                        if let Err(error) = case.save() {
                            self.error = Some(error);
                            self.queue_paused = true;
                        }
                        self.batch_finished += 1;
                        cx.notify();
                        if self.queue_paused {
                            return;
                        }
                        continue;
                    }
                }
            }
            let native = volgui::analysis::is_native(&case.document.runs[i].plugin);
            if !native && engine.is_none() {
                return;
            }
            let evidence = case
                .document
                .evidence
                .iter()
                .find(|e| e.id == case.document.runs[i].evidence_id)
                .unwrap();
            if !volgui::analysis::quarantine::is_passive(&case.document.runs[i])
                && let Err(e) = evidence.check_metadata()
            {
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
            let checkpoint = match case.save_checkpoint() {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    case.document.runs[i].status = RunStatus::Queued;
                    case.document.runs[i].started_at = None;
                    self.error = Some(error);
                    self.queue_paused = true;
                    return;
                }
            };
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
                if let Err(error) = checkpoint.wait(&cancel) {
                    let _ = tx.send(Event::Finished(
                        run.id,
                        Outcome {
                            status: if cancel.load(Ordering::Relaxed) {
                                RunStatus::Cancelled
                            } else {
                                RunStatus::Failed
                            },
                            exit_code: None,
                            table: None,
                            message: error,
                        },
                    ));
                    return;
                }
                let mut outcome = if native {
                    volgui::analysis::execute(
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
                if let Err(error) = volgui::object_store::ObjectStore::at(&case_directory)
                    .capture_run(&run.id, &cancel)
                {
                    outcome.status = if cancel.load(Ordering::Relaxed) {
                        RunStatus::Cancelled
                    } else if outcome.table.is_some() {
                        RunStatus::Warning
                    } else {
                        RunStatus::Failed
                    };
                    // Parsed observations remain evidence even if output bytes
                    // cannot be archived, for example after antivirus quarantine.
                    outcome.warn(&format!("Could not archive analysis output: {error}. Available capture files and parsed results retained."));
                }
                if let Err(error) = outcome.check_output_coverage(&directory) {
                    outcome.warn(&format!("Output coverage could not be checked: {error}. Inspect the archived outputs before running again."));
                }
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
