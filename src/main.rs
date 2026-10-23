#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod ui;

use gpui_kit::{
    component::{Theme, ThemeMode, TitleBar},
    *,
};

fn main() {
    let mut engine = None;
    let mut case = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--volatility") => {
                engine = Some(
                    args.next()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| usage(2)),
                )
            }
            Some("--case") => {
                case = Some(
                    args.next()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| usage(2)),
                )
            }
            Some("--help" | "-h") => usage(0),
            _ => {
                eprintln!(
                    "Usage: volgui-again [--volatility <executable-or-directory>] [--case <case-directory>]"
                );
                std::process::exit(2);
            }
        }
    }
    application().with_assets(assets::AllAssets).run(move |cx| {
        init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        Theme::update(cx, |theme| {
            theme.colors.primary = rgb(0xa83e5c).into();
            theme.colors.primary_foreground = rgb(0xffffff).into();
            theme.colors.primary_hover = rgb(0xc14e70).into();
            theme.colors.primary_active = rgb(0x90314c).into();
            theme.colors.button_primary = rgb(0xa83e5c).into();
            theme.colors.button_primary_hover = rgb(0xc14e70).into();
            theme.colors.button_primary_active = rgb(0x90314c).into();
            theme.colors.button_primary_foreground = rgb(0xffffff).into();
            theme.colors.accent = rgb(0x30212a).into();
            theme.list.active_highlight = false;
            theme.colors.ring = rgb(0xc86280).into();
        });
        let mut options = TitleBar::window_options();
        options.window_bounds = Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(1440.), px(940.)),
            cx,
        )));
        options.window_min_size = Some(size(px(1000.), px(680.)));
        open_window(options, cx, move |window, cx| {
            cx.new(|cx| ui::Workspace::new(engine, case, window, cx))
        })
        .expect("Failed to open VolGUI window");
    });
}

fn usage(code: i32) -> ! {
    eprintln!(
        "Usage: volgui-again [--volatility <executable-or-directory>] [--case <case-directory>]"
    );
    std::process::exit(code)
}
