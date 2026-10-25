use super::*;
use volgui::{case::Run, investigation};

impl Workspace {
    pub(super) fn collect_browser_processes(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = (|| {
            let evidence = self.evidence().ok_or("Select evidence first")?;
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure Volatility in settings")?;
            let output = self
                .case
                .as_ref()
                .ok_or("Open a case first")?
                .directory
                .join("analyses");
            ["windows.pslist.PsList", "windows.cmdline.CmdLine"]
                .into_iter()
                .map(|plugin| engine.prepare(evidence, plugin, vec![], &output))
                .collect::<Result<Vec<_>, _>>()
        })();
        match result {
            Ok(runs) => self.queue_investigation(runs, window, cx),
            Err(error) => {
                self.error = Some(error);
                cx.notify();
            }
        }
    }

    pub(super) fn recover_browser_memory(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() {
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
        let cancel = self.start("Finding browser processes to recover", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = investigation::browser_memory_runs(
                &directory, &document, &evidence, &engine, &cancel,
            );
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
                .ok_or("Configure Volatility in settings")?;
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
            investigation::prepare(evidence, investigation::STRINGS, arguments)
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

    pub(super) fn analyze_browser(
        &mut self,
        recover: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.busy.as_ref().is_some_and(|b| b.run_id.is_none()) {
            return;
        }
        let Some(evidence) = self.evidence().cloned() else {
            return;
        };
        if !recover {
            match investigation::prepare(&evidence, investigation::BROWSER, vec![]) {
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
            return;
        }
        // Preparation reads the file index, so it also belongs on the background worker.
        if self.busy.is_some() {
            return;
        }
        let Some(engine) = self.installation.clone() else {
            self.error = Some("Configure Volatility to recover browser files. Existing extractions can be analyzed without an engine.".into());
            cx.notify();
            return;
        };
        let Some(case) = &self.case else { return };
        let directory = case.directory.clone();
        let document = case.document.clone();
        let physical = self.file_offset_physical;
        let cancel = self.start("Finding browser files to recover", None);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = investigation::browser_recovery_runs(
                &directory, &document, &evidence, &engine, physical, &cancel,
            );
            let _ = tx.send(Event::BrowserPrepared(result));
        });
        cx.notify();
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
                investigation::registry::child_key(source, &record.record)
                    .ok_or("Select a registry subkey")?
            } else {
                self.registry_key.read(cx).value().to_string()
            };
            let arguments = investigation::registry::arguments(&record.record, &key, recurse)?;
            if let Some(cached) = investigation::registry::cached(case, source, &arguments) {
                return Ok((cached.id.clone(), None));
            }
            let engine = self
                .installation
                .as_ref()
                .ok_or("Configure Volatility to read registry keys that have not been collected")?;
            let requested = investigation::registry::prepare(
                case,
                engine,
                source,
                &record.record,
                &key,
                recurse,
            )?;
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
            let engine = self.installation.as_ref().ok_or("Configure Volatility")?;
            let plugin = match evidence.operating_system {
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
