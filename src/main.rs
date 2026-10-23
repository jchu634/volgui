#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
extern crate gpui_kit as gpui;
mod backend;
use backend::{Event, Report, Table};
use gpui_kit::component::{
    Disableable,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
};
use gpui_kit::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant},
};

const ANALYSES: &[(&str, &str)] = &[
    ("Windows / System information", "windows.info.Info"),
    ("Windows / Processes", "windows.pslist.PsList"),
    ("Windows / Process tree", "windows.pstree.PsTree"),
    ("Windows / Process scan", "windows.psscan.PsScan"),
    ("Windows / Command lines", "windows.cmdline.CmdLine"),
    ("Windows / Network connections", "windows.netscan.NetScan"),
    ("Windows / Loaded DLLs", "windows.dlllist.DllList"),
    ("Windows / File scan", "windows.filescan.FileScan"),
    (
        "Windows / Registry hives",
        "windows.registry.hivelist.HiveList",
    ),
    ("Linux / Processes", "linux.pslist.PsList"),
    ("Linux / Process tree", "linux.pstree.PsTree"),
    ("Linux / Shell history", "linux.bash.Bash"),
    ("macOS / Processes", "mac.pslist.PsList"),
    ("macOS / Shell history", "mac.bash.Bash"),
];

struct Volgui {
    engine: Entity<InputState>,
    image: Entity<InputState>,
    output: Entity<InputState>,
    options: Entity<InputState>,
    filter: Entity<InputState>,
    selected: usize,
    offline: bool,
    status: String,
    logs: String,
    table: Option<Table>,
    report: Option<Report>,
    receiver: Option<Receiver<Event>>,
    worker: Option<std::thread::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    help: bool,
    _subscriptions: Vec<Subscription>,
}
impl Volgui {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        window.set_window_title("Volgui · Volatility 3");
        let engine = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(backend::default_engine().to_string_lossy().to_string())
        });
        let image = cx.new(|cx| InputState::new(window, cx).placeholder("Select a memory image…"));
        let output = cx.new(|cx| {
            InputState::new(window, cx).default_value(
                std::env::current_dir()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            )
        });
        let options =
            cx.new(|cx| InputState::new(window, cx).placeholder("Analysis options, e.g. --pid 4"));
        let filter = cx.new(|cx| InputState::new(window, cx).placeholder("Filter result rows…"));
        let subscription = cx.subscribe(&filter, |_, _, _: &InputEvent, cx| cx.notify());
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                if this.update(cx, |this, cx| this.poll(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        Self {
            engine,
            image,
            output,
            options,
            filter,
            selected: 0,
            offline: false,
            status: "Ready · select a memory image to begin".into(),
            logs: String::new(),
            table: None,
            report: None,
            receiver: None,
            worker: None,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            help: false,
            _subscriptions: vec![subscription],
        }
    }
    fn run(&mut self, help: bool, cx: &mut Context<Self>) {
        if self.receiver.is_some() {
            return;
        }
        let args = if help {
            Ok(vec![ANALYSES[self.selected].1.into(), "--help".into()])
        } else {
            backend::analysis_args(
                &self.image.read(cx).value(),
                &self.output.read(cx).value(),
                ANALYSES[self.selected].1,
                &self.options.read(cx).value(),
                self.offline,
            )
        };
        let args = match args {
            Ok(a) => a,
            Err(e) => {
                self.status = e;
                cx.notify();
                return;
            }
        };
        let (tx, rx) = mpsc::channel();
        self.cancel = Arc::new(AtomicBool::new(false));
        self.receiver = Some(rx);
        self.table = None;
        self.report = None;
        self.logs.clear();
        self.help = help;
        self.started = Some(Instant::now());
        self.status = "Running…".into();
        self.worker = Some(backend::launch(
            self.engine.read(cx).value().to_string(),
            args,
            self.cancel.clone(),
            tx,
        ));
        cx.notify();
    }
    fn poll(&mut self, cx: &mut Context<Self>) {
        let events: Vec<_> = self
            .receiver
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for event in events {
            match event {
                Event::Progress(logs) => self.logs = logs,
                Event::Finished(result) => {
                    self.receiver = None;
                    if let Some(worker) = self.worker.take() {
                        let _ = worker.join();
                    }
                    match result {
                        Err(e) => self.status = e,
                        Ok(mut report) => {
                            self.logs =
                                backend::tail(report.stderr.path(), 12000).unwrap_or_default();
                            self.status = if report.cancelled {
                                "Cancelled".into()
                            } else if report.success {
                                format!(
                                    "Completed in {:.1}s",
                                    self.started
                                        .map(|t| t.elapsed().as_secs_f64())
                                        .unwrap_or_default()
                                )
                            } else {
                                format!(
                                    "Volatility exited with {} · see diagnostics",
                                    report
                                        .code
                                        .map(|c| c.to_string())
                                        .unwrap_or("no exit code".into())
                                )
                            };
                            if self.help {
                                self.logs = format!(
                                    "{}\n{}",
                                    backend::tail(report.stdout.path(), 60000).unwrap_or_default(),
                                    self.logs
                                );
                            } else if report.success && !report.cancelled {
                                match std::mem::replace(&mut report.preview, Err(String::new())) {
                                    Ok(table) => self.table = Some(table),
                                    Err(e) => self.status = format!("{} · {e}", self.status),
                                }
                            }
                            self.report = Some(report);
                        }
                    }
                }
            }
            cx.notify();
        }
    }
    fn export(&mut self, cx: &mut Context<Self>) {
        if let Some(report) = &self.report {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name(if self.help {
                    "volatility-help.txt"
                } else {
                    "volatility-results.json"
                })
                .save_file()
            {
                self.status = match std::fs::copy(report.stdout.path(), path) {
                    Ok(_) => "Results exported".into(),
                    Err(e) => format!("Export failed: {e}"),
                };
                cx.notify();
            }
        }
    }
    fn browse(&mut self, field: usize, window: &mut Window, cx: &mut Context<Self>) {
        let dialog = rfd::FileDialog::new();
        let path = if field == 2 {
            dialog.pick_folder()
        } else {
            dialog.pick_file()
        };
        if let Some(path) = path {
            let state = match field {
                0 => &self.engine,
                1 => &self.image,
                _ => &self.output,
            };
            state.update(cx, |s, cx| {
                s.set_value(path.to_string_lossy().to_string(), window, cx)
            });
        }
    }
}
impl Drop for Volgui {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn label(text: impl Into<SharedString>) -> Div {
    div().text_xs().text_color(rgb(0x8c9bab)).child(text.into())
}
fn panel() -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .bg(rgb(0x141e2b))
        .border_1()
        .border_color(rgb(0x283546))
        .rounded_lg()
}
impl Render for Volgui {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let busy = self.receiver.is_some();
        let selected = self.selected;
        let filter = self.filter.read(cx).value().to_lowercase();
        let mut rows = div().flex().flex_col().min_w_0();
        if let Some(table) = &self.table {
            rows = rows.child(
                div()
                    .flex()
                    .bg(rgb(0x223247))
                    .children(table.columns.iter().map(|c| {
                        div()
                            .w(px(180.))
                            .flex_shrink_0()
                            .p_2()
                            .text_sm()
                            .child(c.clone())
                    })),
            );
            for (i, row) in table
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| {
                    filter.is_empty() || r.iter().any(|v| v.to_lowercase().contains(&filter))
                })
                .take(500)
            {
                rows = rows.child(
                    div()
                        .flex()
                        .bg(rgb(if i % 2 == 0 { 0x141e2b } else { 0x192433 }))
                        .children(row.iter().map(|cell| {
                            div()
                                .w(px(180.))
                                .flex_shrink_0()
                                .p_2()
                                .text_sm()
                                .overflow_hidden()
                                .child(cell.clone())
                        })),
                );
            }
        } else {
            rows = rows.child(div().p_8().text_color(rgb(0x8c9bab)).child(if busy {
                "Analysing memory… Diagnostics appear below."
            } else {
                "Run an analysis to explore its results here."
            }));
        }
        let mut settings = panel();
        for (i, (title, state)) in [
            ("ENGINE EXECUTABLE", &self.engine),
            ("MEMORY IMAGE", &self.image),
            ("OUTPUT DIRECTORY · extracted files", &self.output),
        ]
        .into_iter()
        .enumerate()
        {
            settings = settings.child(label(title)).child(
                div()
                    .flex()
                    .gap_2()
                    .child(Input::new(state).disabled(busy))
                    .child(
                        Button::new(("browse", i))
                            .label("Browse")
                            .disabled(busy)
                            .on_click(
                                cx.listener(move |this, _, window, cx| this.browse(i, window, cx)),
                            ),
                    ),
            );
        }
        div().size_full().flex().flex_col().bg(rgb(0x0c1420)).text_color(rgb(0xe4ebf3)).font_family("Segoe UI")
            .child(div().flex().items_center().justify_between().p_5().border_b_1().border_color(rgb(0x283546))
                .child(div().flex().flex_col().gap_1().child(div().text_xl().child("VOLGUI")).child(label("MEMORY FORENSICS / VOLATILITY 3"))).child(label("External CLI engine")))
            .child(div().flex().flex_1().min_h_0()
                .child(div().w(px(245.)).flex_shrink_0().p_3().id("analyses").overflow_y_scroll().children(ANALYSES.iter().enumerate().map(|(i, &(name, _))| {
                    div().id(("analysis", i)).p_3().mb_1().rounded_md().cursor_pointer().bg(rgb(if selected == i { 0x224351 } else { 0x111c29 })).text_sm().child(name)
                        .on_click(cx.listener(move |this, _, _, cx| { if this.receiver.is_none() { this.selected = i; cx.notify(); } }))
                })))
                .child(div().flex().flex_col().flex_1().min_w_0().gap_3().p_4().id("workspace").overflow_y_scroll()
                    .child(settings)
                    .child(panel().child(div().text_lg().child(ANALYSES[selected].0)).child(label(ANALYSES[selected].1)).child(Input::new(&self.options).disabled(busy))
                        .child(div().flex().gap_2().child(Button::new("run").primary().label("Run analysis").disabled(busy).on_click(cx.listener(|this, _, _, cx| this.run(false, cx))))
                            .child(Button::new("help").label("Options help").disabled(busy).on_click(cx.listener(|this, _, _, cx| this.run(true, cx))))
                            .child(Button::new("offline").label(if self.offline { "Offline: on" } else { "Offline: off" }).disabled(busy).on_click(cx.listener(|this, _, _, cx| { this.offline = !this.offline; cx.notify(); })))
                            .child(Button::new("cancel").label("Cancel").disabled(!busy).on_click(cx.listener(|this, _, _, cx| { this.cancel.store(true, Ordering::Relaxed); this.status = "Cancelling…".into(); cx.notify(); }))))
                        .child(label("Offline mode prevents symbol downloads. Symbols must already be cached.")))
                    .child(panel().child(div().flex().items_center().justify_between().child(div().text_lg().child("Results")).child(Button::new("export").label("Export full output").disabled(self.report.is_none() || busy).on_click(cx.listener(|this, _, _, cx| this.export(cx)))))
                        .child(Input::new(&self.filter))
                        .child(label(self.table.as_ref().map(|t| format!("{}{} preview rows · up to 500 matches displayed · export preserves full output", t.rows.len(), if t.truncated { "+" } else { "" })).unwrap_or_default()))
                        .child(div().id("results").h(px(310.)).overflow_scroll().child(rows)))
                    .child(panel().child(label(if self.help { "ANALYSIS HELP" } else { "DIAGNOSTICS · STDERR" })).child(div().id("logs").h(px(150.)).overflow_y_scroll().text_sm().child(self.logs.clone())))))
            .child(div().px_5().py_3().border_t_1().border_color(rgb(0x283546)).text_sm().child(self.status.clone()))
    }
}
fn main() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx| {
            gpui_kit::init(cx);
            gpui_kit::component::Theme::change(gpui_kit::component::ThemeMode::Dark, None, cx);
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                        None,
                        size(px(1280.), px(940.)),
                        cx,
                    ))),
                    ..Default::default()
                },
                cx,
                |window, cx| cx.new(|cx| Volgui::new(window, cx)),
            )
            .expect("Could not open Volgui window");
            cx.activate(true);
        });
}
