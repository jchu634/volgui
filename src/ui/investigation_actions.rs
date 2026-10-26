use super::*;
use volgui::{analysis, case::Run};

impl Workspace {
    pub(super) fn analyze_downloads(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine in settings")?;
            let case = self.case.as_ref().ok_or("Open a case first")?;
            let mut draft = AnalysisDraft::new(evidence);
            draft.selected.insert(analysis::DOWNLOADS.into());
            draft.prepare_in_case(engine, evidence, case)
        })();
        match result {
            Ok(runs) => {
                let report = runs.last().map(|r| r.id.clone());
                self.queue_investigation(runs, window, cx);
                if let Some(report) = report {
                    self.select_run(report, window, cx);
                }
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn open_investigation_bytes(&mut self, offset: u64, cx: &mut Context<Self>) {
        if let Some(evidence) = self.evidence() {
            let path = evidence.path.clone();
            self.open_hex_file(vec![path.clone()], path, offset, cx);
        }
    }

    pub(super) fn investigate_pid_network(
        &mut self,
        pid: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.choose_group(ArtifactGroup::Network, window, cx);
        // Network's graph and sidebar share the same scoped records and search.
        self.query.update(cx, |input, cx| {
            input.set_value(format!("pid:{pid}"), window, cx)
        });
        self.start_query(cx);
    }
    pub(super) fn load_network_bytes(&mut self, cx: &mut Context<Self>) {
        let target = self.case.as_ref().and_then(|case| {
            let record = self.selected.as_ref()?;
            if record.record.text("Source type") != "Residual memory string" {
                return None;
            }
            let offset = record
                .record
                .fields
                .get("Match offset")
                .or_else(|| record.record.fields.get("Offset"))?
                .as_u64()?;
            let run = case.document.runs.iter().find(|r| r.id == record.run_id)?;
            let evidence = case
                .document
                .evidence
                .iter()
                .find(|e| e.id == run.evidence_id)?;
            Some((evidence.path.clone(), offset))
        });
        if let Some((path, offset)) = target {
            self.open_hex_file(vec![path.clone()], path, offset, cx);
        }
    }
    pub(super) fn analyze_network(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine in settings")?;
            let case = self.case.as_ref().ok_or("Open a case first")?;
            let mut draft = AnalysisDraft::new(evidence);
            draft.selected.insert(analysis::NETWORK.into());
            draft.prepare_in_case(engine, evidence, case)
        })();
        match result {
            Ok(runs) => {
                self.content_sidebar_visible = true;
                self.queue_investigation(runs, window, cx);
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }
    pub(super) fn open_application_dump(&mut self, cx: &mut Context<Self>) {
        let pid = self.application_pid.read(cx).value().trim().to_string();
        let source = self.case.as_ref().and_then(|case| {
            case.document
                .runs
                .iter()
                .rev()
                .find(|run| {
                    Some(&run.evidence_id) == self.selected_evidence.as_ref()
                        && run.plugin == analysis::application::MEMMAP
                        && run.status == RunStatus::Completed
                        && run.arguments == ["--pid".to_string(), pid.clone(), "--dump".to_string()]
                })
                .map(|run| case.run_dir(&run.id).join(format!("pid.{pid}.dmp")))
        });
        if let Some(path) = source {
            self.open_hex_file(vec![path.clone()], path, 0, cx);
        } else {
            self.error =
                Some("No completed memory dump for this PID. Scan the process first.".into());
            cx.notify();
        }
    }
    pub(super) fn scan_application_memory(
        &mut self,
        pid: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let pid = pid.unwrap_or_else(|| self.application_pid.read(cx).value().trim().to_string());
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine in settings")?;
            let case = self.case.as_ref().ok_or("Open a case first")?;
            let mut draft = AnalysisDraft::new(evidence);
            draft.selected.insert(analysis::APPLICATION.into());
            draft.arguments.insert(
                analysis::APPLICATION.into(),
                volgui::volatility::format_arguments(&["--pid".into(), pid.clone()]),
            );
            draft.prepare_in_case(engine, evidence, case)
        })();
        match result {
            Ok(runs) => {
                let id = runs.last().map(|r| r.id.clone());
                self.application_pid
                    .update(cx, |input, cx| input.set_value(pid, window, cx));
                self.queue_investigation(runs, window, cx);
                if let Some(id) = id {
                    self.select_run(id, window, cx);
                }
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn step_application_match(&mut self, forward: bool, cx: &mut Context<Self>) {
        let current = self
            .selected
            .as_ref()
            .and_then(|record| self.index.ids.iter().position(|id| *id == record.id));
        let index = match (current, forward) {
            (Some(index), true) => index.saturating_add(1),
            (Some(index), false) => index.saturating_sub(1),
            _ => 0,
        };
        if let Some(id) = self.index.ids.get(index).copied() {
            self.load_record(id, cx);
        }
    }

    pub(super) fn recover_and_analyze_browser(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine in settings")?;
            let output = self
                .case
                .as_ref()
                .ok_or("Open a case first")?
                .directory
                .join("analyses");
            [
                "windows.pslist.PsList",
                "windows.cmdline.CmdLine",
                "windows.filescan.FileScan",
            ]
            .into_iter()
            .map(|plugin| engine.prepare(evidence, plugin, vec![], &output))
            .collect::<Result<Vec<_>, _>>()
        })();
        match result {
            Ok(runs) => {
                self.browser_recovery_pending = true;
                self.queue_investigation(runs, window, cx);
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn prepare_browser_recovery(&mut self, cx: &mut Context<Self>) {
        if self.is_working() {
            return;
        }
        let (Some(evidence), Some(engine), Some(case)) = (
            self.evidence().cloned(),
            self.installation.clone(),
            self.case.as_ref(),
        ) else {
            return;
        };
        let directory = case.directory.clone();
        let document = case.document.clone();
        let cancel = self.start("Finding browser processes to recover");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = (|| {
                let mut runs = match analysis::browser_memory_runs(
                    &directory, &document, &evidence, &engine, &cancel,
                ) {
                    Ok(runs) => runs,
                    Err(error)
                        if error
                            == "Collect browser processes first, then recover browser memory" =>
                    {
                        Vec::new()
                    }
                    Err(error) => return Err(error),
                };
                runs.retain(|run| run.plugin != analysis::BROWSER);
                runs.extend(analysis::browser_recovery_runs(
                    &directory, &document, &evidence, &engine, false, &cancel,
                )?);
                Ok(runs)
            })();
            let _ = tx.send(Event::BrowserPrepared(result));
        });
        cx.notify();
    }

    pub(super) fn collect_source(
        &mut self,
        plugin: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine in settings")?;
            let case = self.case.as_ref().ok_or("Open a case first")?;
            engine.prepare(evidence, plugin, vec![], &case.directory.join("analyses"))
        })();
        match result {
            Ok(run) => {
                let id = run.id.clone();
                self.queue_investigation(vec![run], window, cx);
                self.select_run(id, window, cx);
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn queue_investigation(
        &mut self,
        runs: Vec<Run>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let count = runs.len();
        let result = self
            .case
            .as_mut()
            .ok_or_else(|| "Open a case first".to_string())
            .and_then(|c| c.queue_batch(runs));
        match result {
            Ok(()) => {
                if self.batch_total == self.batch_finished {
                    self.batch_total = 0;
                    self.batch_finished = 0;
                }
                self.batch_total += count;
                self.message = format!("Queued {count} investigation analyses");
                self.start_next(window, cx);
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    pub(super) fn run_string_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let mut arguments = vec![self.string_needle.read(cx).value().to_string()];
            if self.string_ignore_case {
                arguments.push("--ignore-ascii-case".into());
            }
            analysis::prepare(evidence, analysis::STRINGS, arguments)
        })();
        match result {
            Ok(run) => {
                let id = run.id.clone();
                self.queue_investigation(vec![run], window, cx);
                self.select_run(id, window, cx);
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn browse_registry(
        &mut self,
        child: bool,
        recurse: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = (|| {
            let case = self.case.as_ref().ok_or("Open a case first")?;
            let record = self
                .selected
                .as_ref()
                .ok_or("Select a registry hive first")?;
            let source = case
                .document
                .runs
                .iter()
                .find(|r| r.id == record.run_id)
                .ok_or("Missing source analysis")?;
            let key = if child {
                analysis::registry::child_key(source, &record.record)
                    .ok_or("Select a registry subkey")?
            } else {
                self.registry_key.read(cx).value().to_string()
            };
            let arguments = analysis::registry::arguments(&record.record, &key, recurse)?;
            if let Some(cached) = analysis::registry::cached(case, source, &arguments) {
                return Ok((cached.id.clone(), None));
            }
            let engine = self.installation.as_ref().ok_or(
                "Configure analysis engine to read registry keys that have not been collected",
            )?;
            let requested =
                analysis::registry::prepare(case, engine, source, &record.record, &key, recurse)?;
            Ok::<_, String>((requested.id.clone(), Some(requested)))
        })();
        match result {
            Ok((id, run)) => {
                if let Some(run) = run {
                    self.queue_investigation(vec![run], window, cx);
                }
                self.select_run(id, window, cx);
            }
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn load_handles(&mut self, offset: usize, cx: &mut Context<Self>) {
        let Some(record) = self.selected.as_ref() else {
            return;
        };
        let pid = ["PID", "Pid", "pid"]
            .iter()
            .map(|key| record.record.text(key))
            .find(|pid| !pid.is_empty());
        let Some(pid) = pid else { return };
        let Some(store) = self.store() else { return };
        let runs = self
            .group_runs(ArtifactGroup::Files)
            .into_iter()
            .filter(|id| {
                self.case.as_ref().is_some_and(|c| {
                    c.document.runs.iter().any(|r| {
                        &r.id == id
                            && matches!(
                                r.plugin.as_str(),
                                "windows.handles.Handles" | "linux.lsof.Lsof" | "mac.lsof.Lsof"
                            )
                    })
                })
            })
            .collect();
        self.handle_epoch += 1;
        let epoch = self.handle_epoch;
        self.handles_loading = true;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::HandlesLoaded(
                epoch,
                store.process_handles(runs, &pid, offset),
            ));
        });
        cx.notify();
    }

    pub(super) fn collect_process_handles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.collect_process_artifacts(false, window, cx);
    }

    pub(super) fn collect_process_files(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.collect_process_artifacts(true, window, cx);
    }

    fn collect_process_artifacts(
        &mut self,
        dump_files: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = (|| {
            let record = self.selected.as_ref().ok_or("Select a process")?;
            let case = self.case.as_ref().ok_or("Open a case")?;
            let source = case
                .document
                .runs
                .iter()
                .find(|r| r.id == record.run_id)
                .ok_or("Missing source analysis")?;
            let evidence = case
                .document
                .evidence
                .iter()
                .find(|e| e.id == source.evidence_id)
                .ok_or("Missing source evidence")?;
            let pid = ["PID", "Pid", "pid"]
                .iter()
                .map(|key| record.record.text(key))
                .find(|p| p.parse::<u64>().is_ok())
                .ok_or("Selected record has no PID")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure analysis engine")?;
            let plugin = match evidence.operating_system {
                OperatingSystem::Windows if dump_files => "windows.dumpfiles.DumpFiles",
                _ if dump_files => return Err("Dump Files requires Windows evidence".into()),
                OperatingSystem::Linux => "linux.lsof.Lsof",
                OperatingSystem::Macos => "mac.lsof.Lsof",
                _ => "windows.handles.Handles",
            };
            engine.prepare(
                evidence,
                plugin,
                vec!["--pid".into(), pid],
                &case.directory.join("analyses"),
            )
        })();
        match result {
            Ok(run) => self.queue_investigation(vec![run], window, cx),
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }
}
