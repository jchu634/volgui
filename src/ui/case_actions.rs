// Handles case setup, evidence imports, and engine validation.
use super::*;

impl Workspace {
    pub(super) fn validate_engine(&mut self, cx: &mut Context<Self>) {
        if self.is_working() || self.has_queued() {
            return;
        }
        let settings = Settings {
            executable: PathBuf::from(self.engine_path.read(cx).value().trim()),
            symbols: PathBuf::from(self.symbol_path.read(cx).value().trim()),
            offline: self.offline,
            max_concurrent_jobs: self.settings.max_concurrent_jobs,
            recent_cases: self.settings.recent_cases.clone(),
        };
        let cancel = self.start("Checking Volatility");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Validated(Installation::discover(settings, &cancel)));
        });
        cx.notify();
    }
    pub(super) fn open_case(
        &mut self,
        path: PathBuf,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.can_switch() {
            return;
        }
        if self.case.as_ref().is_some_and(|c| {
            path.canonicalize()
                .ok()
                .is_some_and(|p| p == c.directory || p == c.directory.join(volgui::case::DATABASE))
        }) {
            self.view = View::Workspace;
            cx.notify();
            return;
        }
        self.start("Opening case");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Opened(Case::open(&path)));
        });
        cx.notify();
    }
    pub(super) fn use_case(&mut self, mut case: Case, window: &mut Window, cx: &mut Context<Self>) {
        if let Err(error) = case.enable_background_saves() {
            self.error = Some(error);
            return;
        }
        self.query_epoch.fetch_add(1, Ordering::Relaxed);
        self.selection_epoch += 1;
        self.selected_evidence = case.document.evidence.first().map(|e| e.id.clone());
        let path = case.directory.join(volgui::case::DATABASE);
        self.case = Some(case);
        self.handles = None;
        self.handles_loading = false;
        self.handle_epoch += 1;
        if self.welcome_open {
            window.close_dialog(cx);
            self.welcome_open = false;
        }
        self.file_dumps.clear();
        self.hex_visible = false;
        self.reset_hex();
        self.selected = None;
        self.selected_run = None;
        self.selected_row = None;
        self.scope.clear();
        self.row_cache.clear();
        self.index = ResultIndex::default();
        self.result_tree = ResultTree::default();
        self.queue_paused = false;
        self.batch_total = 0;
        self.batch_finished = 0;
        self.view = View::Workspace;
        self.artifact_choices.clear();
        self.message = "Case opened".into();
        window.set_window_title("VolGUI");
        if let Err(e) = self.settings.remember(path) {
            self.error = Some(e);
        }
        self.sync_os();
        if !self.group_runs(self.browser_group).is_empty() {
            self.choose_group(self.browser_group, window, cx);
        } else if let Some(id) = self
            .case
            .as_ref()
            .unwrap()
            .document
            .runs
            .iter()
            .rev()
            .find(|r| r.status == RunStatus::Completed)
            .map(|r| r.id.clone())
        {
            self.select_run(id, window, cx);
        }
        self.back_stack.clear();
    }
    pub(super) fn sync_os(&mut self) {
        if let Some(os) = self
            .evidence()
            .map(|e| e.operating_system)
            .filter(|o| *o != OperatingSystem::Unknown)
        {
            self.plugin_os = os;
        }
    }
    pub(super) fn create_case(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_switch() {
            return;
        }
        let parent = PathBuf::from(self.case_directory.read(cx).value().trim());
        if parent.as_os_str().is_empty() {
            self.error = Some("Choose a folder to create the case in".into());
            return;
        }
        let name = self.case_name.read(cx).value().to_string();
        if name.trim().is_empty() {
            self.error = Some("Enter a case name".into());
            return;
        }
        self.start("Creating case");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Opened(Case::create_named(&parent, &name)));
        });
        cx.notify();
    }
    pub(super) fn choose_path(
        &mut self,
        purpose: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let dirs = matches!(purpose, "directory" | "symbols");
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: !dirs,
            directories: dirs,
            multiple: purpose == "evidence",
            prompt: Some(
                match purpose {
                    "open" => "Open case.sqlite",
                    "evidence" => "Add memory images",
                    "engine" => "Choose Volatility executable",
                    "symbols" => "Choose symbols directory",
                    _ => "Choose case directory",
                }
                .into(),
            ),
        });
        cx.spawn_in(window, async move |this, cx| match receiver.await {
            Ok(Ok(Some(paths))) => {
                let _ = cx.update(|window, cx| {
                    this.update(cx, |this, cx| {
                        if paths.is_empty() {
                            return;
                        }
                        match purpose {
                            "open" => this.open_case(paths[0].clone(), window, cx),
                            "evidence" => this.import(paths, cx),
                            _ => {
                                let field = match purpose {
                                    "engine" => &this.engine_path,
                                    "symbols" => &this.symbol_path,
                                    _ => &this.case_directory,
                                };
                                field.update(cx, |s, cx| {
                                    s.set_value(paths[0].display().to_string(), window, cx)
                                });
                            }
                        }
                        cx.notify();
                    })
                });
            }
            Ok(Err(e)) => {
                let _ = this.update(cx, |this, cx| {
                    this.error = Some(e.to_string());
                    cx.notify();
                });
            }
            _ => {}
        })
        .detach();
    }
    pub(super) fn import(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        if self.case.is_none() || self.is_working() {
            return;
        }
        let cancel = self.start("Hashing evidence");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut results = vec![];
            for path in paths {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let mut last = Instant::now() - Duration::from_secs(1);
                results.push(Evidence::inspect(&path, &cancel, |n, total| {
                    if last.elapsed() > Duration::from_millis(250) {
                        let _ = tx.send(Event::Progress(format!(
                            "Hashing {} · {:.0}%",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            n as f64 / total as f64 * 100.
                        )));
                        last = Instant::now();
                    }
                }));
            }
            let _ = tx.send(Event::Imported(results));
        });
        cx.notify();
    }
    pub(super) fn verify(&mut self, cx: &mut Context<Self>) {
        if self.is_working() {
            return;
        }
        let Some(e) = self.evidence().cloned() else {
            return;
        };
        let cancel = self.start("Verifying evidence");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = Evidence::inspect(&e.path, &cancel, |_, _| {});
            let _ = tx.send(Event::Verified(e.id, result));
        });
        cx.notify();
    }
}
